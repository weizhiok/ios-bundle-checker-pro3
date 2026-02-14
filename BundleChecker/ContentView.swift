import SwiftUI
import Security
import Foundation
import Darwin

// ========================================================================
// 🛠️ C-Bridge 定义区 (底层 C 函数映射)
// ========================================================================

// 1. dladdr 结构体与函数 (用于 Runtime 检测)
struct Local_Dl_info {
    var dli_fname: UnsafePointer<CChar>?
    var dli_fbase: UnsafeMutableRawPointer?
    var dli_sname: UnsafePointer<CChar>?
    var dli_saddr: UnsafeMutableRawPointer?
}

func safe_dladdr(_ addr: UnsafeRawPointer, _ info: UnsafeMutablePointer<Local_Dl_info>) -> Int32 {
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    guard let sym = dlsym(RTLD_DEFAULT, "dladdr") else { return 0 }
    typealias DlAddrFunc = @convention(c) (UnsafeRawPointer, UnsafeMutableRawPointer) -> Int32
    let dladdr_real = unsafeBitCast(sym, to: DlAddrFunc.self)
    let infoRaw = UnsafeMutableRawPointer(info)
    return dladdr_real(addr, infoRaw)
}

// 2. Security / Kernel 定义
typealias SecTaskRef = AnyObject
typealias SecCodeRef = AnyObject

@_silgen_name("SecTaskCreateFromSelf")
func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?

@_silgen_name("SecTaskCopySigningIdentifier")
func SecTaskCopySigningIdentifier(_ task: SecTaskRef, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?

@_silgen_name("SecTaskCopyValueForEntitlement")
func SecTaskCopyValueForEntitlement(_ task: SecTaskRef, _ entitlement: CFString, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFTypeRef?

@_silgen_name("SecCodeCopySelf")
func SecCodeCopySelf(_ flags: UInt32, _ code: UnsafeMutablePointer<SecCodeRef?>) -> Int32

@_silgen_name("SecCodeCopySigningInformation")
func SecCodeCopySigningInformation(_ code: SecCodeRef, _ flags: UInt32, _ info: UnsafeMutablePointer<CFDictionary?>?) -> Int32

// ========================================================================
// 📱 主程序入口
// ========================================================================

@main
struct BundleCheckerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

// ========================================================================
// 🖥️ 视图与逻辑
// ========================================================================

struct ContentView: View {
    @State private var results: [ResultItem] = []
    @State private var isLoading = true
    
    // 🎯 【核心设置】你的原始 BundleID
    // 只有检测结果不等于这个值时，才会报红
    let targetBundleID = "com.user.bundlechecker"

    struct ResultItem: Hashable, Identifiable {
        let id = UUID()
        let method: String
        let value: String
        let detail: String
        let status: Status
    }

    enum Status {
        case safe       // 正常 (黑色/绿色)
        case suspicious // 异常 (红色) - 只有 ID 不匹配才用这个
        case info       // 信息 (蓝色/灰色) - 用于展示证书等不可控信息
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 篡改检测")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
            
            if isLoading {
                VStack {
                    ProgressView()
                        .padding()
                    Text("正在提取签名指纹...")
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
        case .safe: return .primary // 正常显示黑色(深色模式白)
        case .suspicious: return .red
        case .info: return .blue
        }
    }

    // ========================================================================
    // 🔍 核心执行逻辑
    // ========================================================================
    
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // --- 第一部分：BundleID 一致性检测 ---
        // 这里的逻辑是：必须等于 com.user.bundlechecker，否则报红
        
        // 1. [OC API] Bundle.main
        let nsID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsID,
            detail: "应用层 API (易被 Hook)",
            status: nsID == targetBundleID ? .safe : .suspicious
        ))
        
        // 2. [C API] CFBundleIdentifier
        let cfID = getCFBundleIdentifier()
        items.append(ResultItem(
            method: "2. [C API] CFBundleGetIdentifier",
            value: cfID,
            detail: "CoreFoundation 底层获取",
            status: cfID == targetBundleID ? .safe : .suspicious
        ))
        
        // 3. [IO] Info.plist (Cocoa)
        let dictID = getDictFromInfo()
        items.append(ResultItem(
            method: "3. [IO] Info.plist 字典读取",
            value: dictID,
            detail: "文件系统层面读取 (Cocoa)",
            status: dictID == targetBundleID ? .safe : .suspicious
        ))
        
        // 4. [IO] fopen (C Standard)
        let fopenID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(
            method: "4. [IO] fopen 直接读取",
            value: fopenID,
            detail: "绕过 Runtime 的文件读取",
            status: fopenID == targetBundleID ? .safe : .suspicious
        ))
        
        // 5. [内核] SecTask
        let kernelID = getSecTaskSigningIdentifier()
        // SecTask 读出来的 ID 有时带 TeamID 前缀，有时不带，这里做个智能剥离
        let cleanKernelID = stripTeamID(kernelID)
        items.append(ResultItem(
            method: "5. [内核] SecTask ID",
            value: kernelID,
            detail: "基于 Entitlements 的内核视角",
            status: cleanKernelID == targetBundleID ? .safe : .suspicious
        ))
        
        // 6. [安全框架] SecCode API
        // 如果获取失败，显示"N/A"但不报红
        let secCodeID = getSecCodeID()
        let secCodeStatus: Status
        if secCodeID == "N/A" || secCodeID.contains("Fail") {
            secCodeStatus = .safe // 获取不到算正常，不吓唬用户
        } else {
            secCodeStatus = stripTeamID(secCodeID) == targetBundleID ? .safe : .suspicious
        }
        items.append(ResultItem(
            method: "6. [安全框架] SecCode API",
            value: secCodeID,
            detail: "Security 静态代码对象",
            status: secCodeStatus
        ))
        
        // --- 第二部分：签名信息展示 (不判红) ---
        // 这里的逻辑是：只展示，永远不报红，因为自签名必然会变
        
        // 7. [授权] Entitlements 字段
        let entID = getEntitlementsAppID()
        items.append(ResultItem(
            method: "7. [授权] application-identifier",
            value: entID,
            detail: "当前签名的授权 ID (展示用)",
            status: .safe // 永远正常
        ))

        // 8. [证书] Provisioning Profile
        let provID = getMobileProvisionID()
        items.append(ResultItem(
            method: "8. [证书] mobileprovision",
            value: provID,
            detail: "当前签名的证书 ID (展示用)",
            status: .safe // 永远正常
        ))
        
        // 9. [Runtime] 方法地址检测
        let (rtStatus, rtMsg) = checkRuntimeIntegrity()
        items.append(ResultItem(
            method: "9. [Runtime] Swizzle 检测",
            value: rtStatus ? "Safe" : "Hooked",
            detail: rtMsg,
            status: rtStatus ? .safe : .suspicious
        ))
        
        self.results = items
    }
    
    // ========================================================================
    // 🛠️ 辅助函数实现
    // ========================================================================
    
    func stripTeamID(_ fullID: String) -> String {
        let components = fullID.components(separatedBy: ".")
        if components.count > 1 && components[0].count == 10 {
            let potentialTeamID = components[0]
            let charset = CharacterSet.alphanumerics
            if potentialTeamID.rangeOfCharacter(from: charset.inverted) == nil {
                return components.dropFirst().joined(separator: ".")
            }
        }
        return fullID
    }
    
    // 1. OC API
    func getCFBundleIdentifier() -> String {
        let mainBundle = CFBundleGetMainBundle()
        if let idRef = CFBundleGetIdentifier(mainBundle) {
            return idRef as String
        }
        return "Fail"
    }
    
    // 2. Dict
    func getDictFromInfo() -> String {
        if let path = Bundle.main.path(forResource: "Info", ofType: "plist"),
           let dict = NSDictionary(contentsOfFile: path),
           let id = dict["CFBundleIdentifier"] as? String {
            return id
        }
        return "Fail"
    }
    
    // 3. fopen
    func getBundleIDFromPlistUsingFopen() -> String {
        guard let path = Bundle.main.path(forResource: "Info", ofType: "plist") else { return "No Path" }
        guard let file = fopen(path, "r") else { return "fopen Fail" }
        defer { fclose(file) }
        fseek(file, 0, SEEK_END)
        let size = ftell(file)
        fseek(file, 0, SEEK_SET)
        if size <= 0 { return "Empty" }
        var buffer = [CChar](repeating: 0, count: Int(size) + 1)
        fread(&buffer, 1, Int(size), file)
        let content = String(cString: buffer)
        if let range = content.range(of: "CFBundleIdentifier") {
            let sub = content[range.upperBound...]
            if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                return String(sub[start.upperBound..<end.lowerBound])
            }
        }
        return "Parse Fail"
    }
    
    // 4. SecTask
    func getSecTaskSigningIdentifier() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "Fail" }
        if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
            return idRef as String
        }
        return "Unknown"
    }
    
    // 5. SecCode
    func getSecCodeID() -> String {
        var code: SecCodeRef? = nil
        // 尝试获取 Code 对象，如果失败直接返回 N/A
        if SecCodeCopySelf(0, &code) == 0, let validCode = code {
            var info: CFDictionary? = nil
            if SecCodeCopySigningInformation(validCode, 1, &info) == 0, let validInfo = info as? [String: Any] {
                if let id = validInfo["identifier"] as? String {
                    return id
                }
            }
        }
        return "N/A"
    }
    
    // 6. Entitlements
    func getEntitlementsAppID() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "Fail" }
        let key = "application-identifier" as CFString
        if let value = SecTaskCopyValueForEntitlement(secTask, key, nil) as? String {
            return value
        }
        return "Not Found"
    }
    
    // 7. Provisioning
    func getMobileProvisionID() -> String {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return "未找到 (可能是模拟器)"
        }
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let content = String(data: data, encoding: .isoLatin1) ?? ""
            if let range = content.range(of: "<key>application-identifier</key>") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    return String(sub[start.upperBound..<end.lowerBound])
                }
            }
        } catch { return "读取错误" }
        return "未找到 ID 字段"
    }
    
    // 8. Runtime Check
    func checkRuntimeIntegrity() -> (Bool, String) {
        let selector = #selector(getter: Bundle.bundleIdentifier)
        guard let method = class_getInstanceMethod(Bundle.self, selector) else {
            return (false, "Method Missing")
        }
        let imp = method_getImplementation(method)
        var info = Local_Dl_info()
        let impPtr = UnsafeRawPointer(imp)
        
        if safe_dladdr(impPtr, &info) != 0 {
            if let fnamePtr = info.dli_fname {
                let fname = String(cString: fnamePtr)
                if fname.contains("CoreFoundation") || fname.contains("Foundation") || fname.contains("libswift") {
                    return (true, "System Framework")
                } else {
                    let libName = URL(fileURLWithPath: fname).lastPathComponent
                    return (false, "Hooked by: \(libName)")
                }
            }
        }
        return (false, "dladdr Failed")
    }
    
}
