import SwiftUI
import Security
import Foundation
import Darwin
import MachO

// ========================================================================
// 🛠️ 核心底层定义区 (C-API 映射 & 结构体)
// ========================================================================

// 1. dladdr 相关 (绕过编译器检查)
struct Local_Dl_info {
    var dli_fname: UnsafePointer<CChar>?
    var dli_fbase: UnsafeMutableRawPointer?
    var dli_sname: UnsafePointer<CChar>?
    var dli_saddr: UnsafeMutableRawPointer?
}

func safe_dladdr(_ addr: UnsafeRawPointer, _ info: UnsafeMutablePointer<Local_Dl_info>) -> Int32 {
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    guard let sym = dlsym(RTLD_DEFAULT, "dladdr") else { return 0 }
    
    // 定义 C 函数指针类型：第二个参数使用 UnsafeMutableRawPointer 绕过 Swift 类型检查
    typealias DlAddrFunc = @convention(c) (UnsafeRawPointer, UnsafeMutableRawPointer) -> Int32
    
    let dladdr_real = unsafeBitCast(sym, to: DlAddrFunc.self)
    let infoRaw = UnsafeMutableRawPointer(info)
    return dladdr_real(addr, infoRaw)
}

// 2. SecTask 相关
typealias SecTaskRef = AnyObject
@_silgen_name("SecTaskCreateFromSelf")
func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?
@_silgen_name("SecTaskCopySigningIdentifier")
func SecTaskCopySigningIdentifier(_ task: SecTaskRef, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?
@_silgen_name("SecTaskCopyValueForEntitlement")
func SecTaskCopyValueForEntitlement(_ task: SecTaskRef, _ entitlement: CFString, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFTypeRef?

// 3. SecCode 相关
typealias SecCodeRef = AnyObject
@_silgen_name("SecCodeCopySelf")
func SecCodeCopySelf(_ flags: UInt32, _ code: UnsafeMutablePointer<SecCodeRef?>) -> Int32
@_silgen_name("SecCodeCopySigningInformation")
func SecCodeCopySigningInformation(_ code: SecCodeRef, _ flags: UInt32, _ info: UnsafeMutablePointer<CFDictionary?>?) -> Int32

// 4. Audit Token 相关
// audit_token_t 定义为 8 个 uint32 (32 bytes)
struct audit_token_t_swift {
    var val: (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32) = (0,0,0,0,0,0,0,0)
}
@_silgen_name("SecTaskCreateFromAuditToken")
func SecTaskCreateFromAuditToken(_ tokenData: UnsafeRawPointer) -> SecTaskRef?

// ========================================================================

@main
struct BundleCheckerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var results: [ResultItem] = []
    @State private var isLoading = true

    struct ResultItem: Hashable, Identifiable {
        let id = UUID()
        let method: String
        let value: String
        let detail: String
        let status: Status
    }

    enum Status {
        case safe       // 黑色: 一致
        case suspicious // 红色: 不一致
        case info       // 蓝色: 仅展示信息
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 终极检测 V7")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
            
            if isLoading {
                VStack {
                    ProgressView()
                        .padding()
                    Text("正在进行全维取证...")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
                .padding()
            } else {
                List {
                    ForEach(results) { item in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(item.method)
                                    .font(.system(size: 14, weight: .bold))
                                    .foregroundColor(.gray)
                                
                                Text(item.value)
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(colorForStatus(item.status))
                                    .textSelection(.enabled)
                                
                                if !item.detail.isEmpty {
                                    Text(item.detail)
                                        .font(.system(size: 10))
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.plain)
            }
        }
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                performAllChecks()
                isLoading = false
            }
        }
    }

    func colorForStatus(_ status: Status) -> Color {
        switch status {
        case .safe: return .primary
        case .suspicious: return .red
        case .info: return .blue
        }
    }

    // ========================================================================
    // 🔍 核心检测逻辑 (10大手段)
    // ========================================================================
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // --- 0. 确立基准 (SecTask) ---
        let kernelID = getSecTaskSigningIdentifier()
        let cleanKernelID = stripTeamID(kernelID)
        
        // 1. [OC API] Bundle.main
        let nsID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsID,
            detail: "最易被 Hook 的应用层 API",
            status: nsID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 2. [C API] CFBundleIdentifier
        let cfID = getCFBundleIdentifier()
        items.append(ResultItem(
            method: "2. [C API] CFBundleGetIdentifier",
            value: cfID,
            detail: "CoreFoundation 底层获取",
            status: cfID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 3. [IO] Info.plist (Cocoa)
        let dictID = getDictFromInfo()
        items.append(ResultItem(
            method: "3. [IO] Info.plist 字典读取",
            value: dictID,
            detail: "文件系统层面读取 (Cocoa)",
            status: dictID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 4. [IO] Info.plist (fopen)
        let fopenID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(
            method: "4. [IO] fopen 直接读取",
            value: fopenID,
            detail: "绕过 OC Runtime 的文件读取",
            status: fopenID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 5. [内核] SecTask
        items.append(ResultItem(
            method: "5. [内核] SecTask ID",
            value: kernelID,
            detail: "基于 Entitlements 的内核视角 (基准)",
            status: .safe
        ))
        
        // 6. [安全框架] SecCode API
        let secCodeID = getSecCodeID()
        items.append(ResultItem(
            method: "6. [安全框架] SecCode API",
            value: secCodeID,
            detail: "Security.framework 代码签名对象",
            status: stripTeamID(secCodeID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 7. [审计] Audit Token
        let auditID = getAuditTokenID()
        items.append(ResultItem(
            method: "7. [审计] Audit Token",
            value: auditID,
            detail: "进程任务审计令牌 (极难伪造)",
            status: stripTeamID(auditID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 8. [二进制] Mach-O __TEXT 段
        let machoID = getMachOEmbeddedInfoID()
        items.append(ResultItem(
            method: "8. [二进制] Mach-O 内嵌信息",
            value: machoID,
            detail: "直接解析可执行文件 __TEXT 段",
            status: machoID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 9. [授权] Entitlements 字段
        let entID = getEntitlementsAppID()
        items.append(ResultItem(
            method: "9. [授权] application-identifier",
            value: entID,
