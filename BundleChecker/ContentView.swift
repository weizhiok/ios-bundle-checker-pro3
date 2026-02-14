import SwiftUI
import Security
import Foundation
import Darwin
import MachO

// ========================================================================
// 🛠️ C-Bridge 定义区
// ========================================================================

// 1. dladdr 结构体与函数
struct Local_Dl_info {
    var dli_fname: UnsafePointer<CChar>?
    var dli_fbase: UnsafeMutableRawPointer?
    var dli_sname: UnsafePointer<CChar>?
    var dli_saddr: UnsafeMutableRawPointer?
}

// 使用 RawPointer 绕过 Swift 类型检查
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

// 【修正点】删除静态声明，改用 dlsym 动态查找，避免 Linker Error
// @_silgen_name("SecTaskCreateFromAuditToken") 
// func SecTaskCreateFromAuditToken(_ tokenData: UnsafeRawPointer) -> SecTaskRef?

// Audit Token 结构 (8个 UInt32)
struct audit_token_t_swift {
    var val: (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32) = (0,0,0,0,0,0,0,0)
}

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

    struct ResultItem: Hashable, Identifiable {
        let id = UUID()
        let method: String
        let value: String
        let detail: String
        let status: Status
    }

    enum Status {
        case safe
        case suspicious
        case info
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 终极检测 V9")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
            
            if isLoading {
                VStack {
                    ProgressView()
                        .padding()
                    Text("正在扫描底层指纹...")
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
    // 🔍 核心执行逻辑
    // ========================================================================
    
    func performAllChecks() {
        var items: [ResultItem] = []
        
        // 0. 基准
        let kernelID = getSecTaskSigningIdentifier()
        let cleanKernelID = stripTeamID(kernelID)
        
        // 1. OC API
        let nsID = Bundle.main.bundleIdentifier ?? "nil"
        items.append(ResultItem(
            method: "1. [OC API] Bundle.main",
            value: nsID,
            detail: "应用层 API (易被 Hook)",
            status: nsID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 2. C API
        let cfID = getCFBundleIdentifier()
        items.append(ResultItem(
            method: "2. [C API] CFBundleGetIdentifier",
            value: cfID,
            detail: "CoreFoundation 底层",
            status: cfID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 3. Dict Read
        let dictID = getDictFromInfo()
        items.append(ResultItem(
            method: "3. [IO] Info.plist 字典",
            value: dictID,
            detail: "Cocoa 文件读取",
            status: dictID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 4. fopen
        let fopenID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(
            method: "4. [IO] fopen 直接读取",
            value: fopenID,
            detail: "C语言标准库读取",
            status: fopenID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 5. SecTask
        items.append(ResultItem(
            method: "5. [内核] SecTask",
            value: kernelID,
            detail: "内核 Entitlements (基准)",
            status: .safe
        ))
        
        // 6. SecCode
        let secCodeID = getSecCodeID()
        items.append(ResultItem(
            method: "6. [安全框架] SecCode API",
            value: secCodeID,
            detail: "Security 静态代码对象",
            status: stripTeamID(secCodeID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 7. Audit Token
        let auditID = getAuditTokenID()
        items.append(ResultItem(
            method: "7. [审计] Audit Token",
            value: auditID,
            detail: "进程任务令牌 (dlsym)",
            status: stripTeamID(auditID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 8. Mach-O
        let machoID = getMachOEmbeddedInfoID()
        items.append(ResultItem(
            method: "8. [二进制] Mach-O",
            value: machoID,
            detail: "解析 __TEXT.__info_plist",
            status: machoID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 9. Entitlements
        let entID = getEntitlementsAppID()
        items.append(ResultItem(
            method: "9. [授权] application-identifier",
            value: entID,
            detail: "直接读取授权字段",
            status: stripTeamID(entID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 10. Provisioning
        let provID = getMobileProvisionID()
        let isProvSafe = provID.contains(cleanKernelID) || provID == kernelID
        items.append(ResultItem(
            method: "10. [证书] mobileprovision",
            value: provID,
            detail: "签名描述文件",
            status: isProvSafe ? .safe : .suspicious
        ))
        
        // 11. Runtime
        let (rtStatus, rtMsg) = checkRuntimeIntegrity()
        items.append(ResultItem(
            method: "11. [Runtime] Swizzle 检测",
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
        if SecCodeCopySelf(0, &code) == 0, let validCode = code {
            var info: CFDictionary? = nil
            if SecCodeCopySigningInformation(validCode, 1, &info) == 0, let validInfo = info as? [String: Any] {
                if let id = validInfo["identifier"] as? String {
                    return id
                }
            }
        }
        return "SecCode Fail"
    }
    
    // 6. Audit Token (动态调用版)
    func getAuditTokenID() -> String {
        var token = audit_token_t_swift()
        var size = mach_msg_type_number_t(MemoryLayout<audit_token_t_swift>.size / 4)
        let kTaskAuditToken: task_flavor_t = 15
        
        let result = withUnsafeMutablePointer(to: &token) { ptr -> Int32 in
            let intPtr = ptr.withMemoryRebound(to: integer_t.self, capacity: Int(size)) { $0 }
            return task_info(mach_task_self_, kTaskAuditToken, intPtr, &size)
        }
        
        if result == 0 {
            // 【修正】使用 dlsym 动态查找 SecTaskCreateFromAuditToken
            let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
            guard let sym = dlsym(RTLD_DEFAULT, "SecTaskCreateFromAuditToken") else {
                return "Symbol Not Found"
            }
            
            // 定义函数指针: SecTaskRef SecTaskCreateFromAuditToken(audit_token_t *token)
            typealias SecTaskCreateFunc = @convention(c) (UnsafeRawPointer) -> Unmanaged<AnyObject>?
            
            let funcPtr = unsafeBitCast(sym, to: SecTaskCreateFunc.self)
            
            return withUnsafePointer(to: &token) { ptr -> String in
                // 调用动态找到的函数
                guard let unmanagedTask = funcPtr(ptr) else { return "Token Invalid" }
                let secTask = unmanagedTask.takeUnretainedValue()
                
                if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
                    return idRef as String
                }
                return "Token No ID"
            }
        }
        return "Task Info Fail"
    }
    
    // 7. Mach-O
    func getMachOEmbeddedInfoID() -> String {
        guard let path = Bundle.main.executablePath else { return "No Exec" }
        guard let file = fopen(path, "r") else { return "Open Fail" }
        defer { fclose(file) }
        
        var header = mach_header_64()
        if fread(&header, MemoryLayout<mach_header_64>.size, 1, file) != 1 { return "Read Header Fail" }
        if header.magic != MH_MAGIC_64 { return "Not 64-bit" }
        
        var cmdOffset = MemoryLayout<mach_header_64>.size
        var lc = load_command()
        
        for _ in 0..<header.ncmds {
            fseek(file, 0, SEEK_SET)
            fseek(file, Int(cmdOffset), SEEK_CUR)
            if fread(&lc, MemoryLayout<load_command>.size, 1, file) != 1 { break }
            
            if lc.cmd == 0x19 { // LC_SEGMENT_64
                fseek(file, 0, SEEK_SET)
                fseek(file, Int(cmdOffset), SEEK_CUR)
                var seg = segment_command_64()
                if fread(&seg, MemoryLayout<segment_command_64>.size, 1, file) != 1 { break }
                
                let segName = withUnsafePointer(to: &seg.segname) {
                    $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                }
                
                if segName == "__TEXT" {
                    var sectOffset = cmdOffset + MemoryLayout<segment_command_64>.size
                    for _ in 0..<seg.nsects {
                        fseek(file, 0, SEEK_SET)
                        fseek(file, Int(sectOffset), SEEK_CUR)
                        var sect = section_64()
                        if fread(&sect, MemoryLayout<section_64>.size, 1, file) != 1 { break }
                        
                        let sectName = withUnsafePointer(to: &sect.sectname) {
                            $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                        }
                        
                        if sectName == "__info_plist" {
                            let size = Int(sect.size)
                            let offset = Int(sect.offset)
                            if size > 0 {
                                fseek(file, 0, SEEK_SET)
                                fseek(file, offset, SEEK_CUR)
                                var buffer = [CChar](repeating: 0, count: size + 1)
                                fread(&buffer, 1, size, file)
                                let content = String(cString: buffer)
                                if let range = content.range(of: "CFBundleIdentifier") {
                                    let sub = content[range.upperBound...]
                                    if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                                        return String(sub[start.upperBound..<end.lowerBound])
                                    }
                                }
                            }
                        }
                        sectOffset += MemoryLayout<section_64>.size
                    }
                }
            }
            cmdOffset += Int(lc.cmdsize)
        }
        return "Not Found"
    }
    
    // 8. Entitlements
    func getEntitlementsAppID() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "Fail" }
        let key = "application-identifier" as CFString
        if let value = SecTaskCopyValueForEntitlement(secTask, key, nil) as? String {
            return value
        }
        return "Not Found"
    }
    
    // 9. Provisioning
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
    
    // 10. Runtime Check
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
