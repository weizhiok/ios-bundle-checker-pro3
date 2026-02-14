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

@_silgen_name("SecTaskCreateFromSelf")
func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?

@_silgen_name("SecTaskCopySigningIdentifier")
func SecTaskCopySigningIdentifier(_ task: SecTaskRef, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?

@_silgen_name("SecTaskCopyValueForEntitlement")
func SecTaskCopyValueForEntitlement(_ task: SecTaskRef, _ entitlement: CFString, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFTypeRef?

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
    // 只有检测结果不等于这个值时，前几项才会报红
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
        case suspicious // 异常 (红色)
        case info       // 信息 (蓝色/灰色)
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 篡改检测 V10")
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
        case .safe: return .primary // 正常
        case .suspicious: return .red   // 异常
        case .info: return .blue    // 信息
        }
    }

    // ========================================================================
    // 🔍 核心执行逻辑
    // ========================================================================
    
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // --- 第一部分：基准检测 (对比 com.user.bundlechecker) ---
        
        // 1. [OC API]
        let nsID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsID,
            detail: "应用层 API (易被 Hook)",
            status: nsID == targetBundleID ? .safe : .suspicious
        ))
        
        // 2. [C API]
        let cfID = getCFBundleIdentifier()
        items.append(ResultItem(
            method: "2. [C API] CFBundleGetIdentifier",
            value: cfID,
            detail: "CoreFoundation 底层获取",
            status: cfID == targetBundleID ? .safe : .suspicious
        ))
        
        // 3. [IO] Info.plist
        let dictID = getDictFromInfo()
        items.append(ResultItem(
            method: "3. [IO] Info.plist 字典读取",
            value: dictID,
            detail: "Cocoa 文件读取",
            status: dictID == targetBundleID ? .safe : .suspicious
        ))
        
        // 4. [IO] fopen
        let fopenID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(
            method: "4. [IO] fopen 直接读取",
            value: fopenID,
            detail: "绕过 Runtime 的文件读取",
            status: fopenID == targetBundleID ? .safe : .suspicious
        ))
        
        // 5. [内核] SecTask
        let kernelID = getSecTaskSigningIdentifier()
        let cleanKernelID = stripTeamID(kernelID)
        items.append(ResultItem(
            method: "5. [内核] SecTask ID",
            value: kernelID,
            detail: "基于 Entitlements 的内核视角",
            status: cleanKernelID == targetBundleID ? .safe : .suspicious
        ))
        
        // --- 第二部分：一致性交叉对比 (授权 vs 证书) ---
        // 这里的逻辑：不管你签成什么样，这两者必须一致，否则红名
        
        // 6. [授权] Entitlements
        let entID = getEntitlementsAppID()
        
        // 7. [证书] Provisioning Profile
        let provID = getMobileProvisionID()
        
        // 核心逻辑：交叉对比
        // 通常 entID 包含 TeamID (如 A1B2.com.x)，provID 也包含。
        // 如果 provID 包含 entID，或者两者完全相等，则视为一致。
        let isSignatureConsistent = (provID == entID) || provID.contains(entID) || entID.contains(provID)
        
        // 如果获取失败（显示 Not Found），也标记为 info 或 suspicious，看你喜好。这里设为 suspicious 提醒注意
        let entStatus: Status = (entID.contains("Fail") || entID.contains("Found")) ? .info : (isSignatureConsistent ? .safe : .suspicious)
        let provStatus: Status = (provID.contains("未找到") || provID.contains("错误")) ? .info : (isSignatureConsistent ? .safe : .suspicious)

        items.append(ResultItem(
            method: "6. [授权] application-identifier",
            value: entID,
            detail: "App 二进制内部权限声明",
            status: entStatus
        ))

        items.append(ResultItem(
            method: "7. [证书] mobileprovision",
            value: provID,
            detail: "App 外部签名文件声明",
            status: provStatus
        ))
        
        // --- 第三部分：环境完整性 ---
        
        // 8. [Runtime] Swizzle 检测
        let (rtStatus, rtMsg) = checkRuntimeIntegrity()
        items.append(ResultItem(
            method: "8. [Runtime] Swizzle 检测",
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
