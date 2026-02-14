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

// 3. SecCode 相关 (新增)
typealias SecCodeRef = AnyObject
@_silgen_name("SecCodeCopySelf")
func SecCodeCopySelf(_ flags: UInt32, _ code: UnsafeMutablePointer<SecCodeRef?>) -> Int32
@_silgen_name("SecCodeCopySigningInformation")
func SecCodeCopySigningInformation(_ code: SecCodeRef, _ flags: UInt32, _ info: UnsafeMutablePointer<CFDictionary?>?) -> Int32

// 4. Audit Token 相关 (新增)
let TASK_AUDIT_TOKEN: Int32 = 15
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
        case safe       // 黑色/绿色: 一致
        case suspicious // 红色: 不一致
        case info       // 蓝色/灰色: 仅展示信息 (如证书文件)
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("BundleID 终极检测 V6")
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
        case .safe: return .primary // 正常显示黑色(深色模式白)
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
        // SecTask 是内核层对当前进程的认知，作为我们判断“是否一致”的标尺
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
        
        // 6. [安全框架] SecCode API (新增)
        let secCodeID = getSecCodeID()
        items.append(ResultItem(
            method: "6. [安全框架] SecCode API",
            value: secCodeID,
            detail: "Security.framework 代码签名对象",
            status: stripTeamID(secCodeID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 7. [审计] Audit Token (新增)
        let auditID = getAuditTokenID()
        items.append(ResultItem(
            method: "7. [审计] Audit Token",
            value: auditID,
            detail: "进程任务审计令牌 (极难伪造)",
            status: stripTeamID(auditID) == cleanKernelID ? .safe : .suspicious
        ))
        
        // 8. [二进制] Mach-O __TEXT 段 (新增 - 硬核)
        let machoID = getMachOEmbeddedInfoID()
        items.append(ResultItem(
            method: "8. [二进制] Mach-O 内嵌信息",
            value: machoID,
            detail: "直接解析可执行文件 __TEXT 段",
            status: machoID == cleanKernelID ? .safe : .suspicious
        ))
        
        // 9. [授权] Entitlements 字段 (新增)
        let entID = getEntitlementsAppID()
        items.append(ResultItem(
            method: "9. [授权] application-identifier",
            value: entID,
            detail: "直接读取授权文件字段",
            status: stripTeamID(entID) == cleanKernelID ? .safe : .suspicious
        ))

        // 10. [证书] Provisioning Profile (已优化判定逻辑)
        let provID = getMobileProvisionID()
        // 逻辑修正：只要证书里的ID包含当前的内核ID，就认为是匹配的（即使是重签名）
        let provStatus: Status = (provID.contains(cleanKernelID) || provID == kernelID) ? .safe : .suspicious
        items.append(ResultItem(
            method: "10. [证书] mobileprovision",
            value: provID,
            detail: "当前签名的描述文件 (仅展示)",
            status: provStatus
        ))
        
        // 11. [Runtime] 方法地址检测
        let (rtStatus, rtMsg) = checkRuntimeIntegrity()
        items.append(ResultItem(
            method: "11. [Runtime] Swizzle 检测",
            value: rtStatus ? "未检测到异常" : "发现 Hook",
            detail: rtMsg,
            status: rtStatus ? .safe : .suspicious
        ))

        self.results = items
    }
    
    // ========================================================================
    // 辅助函数与实现
    // ========================================================================
    
    func stripTeamID(_ fullID: String) -> String {
        let components = fullID.components(separatedBy: ".")
        if components.count > 1 && components[0].count == 10 {
            // 假设 TeamID 是 10 位 (如 A1B2C3D4E5)
            // 简单的启发式过滤
            let potentialTeamID = components[0]
            let charset = CharacterSet.alphanumerics
            if potentialTeamID.rangeOfCharacter(from: charset.inverted) == nil {
                return components.dropFirst().joined(separator: ".")
            }
        }
        return fullID
    }

    // --- 1. CFBundle ---
    func getCFBundleIdentifier() -> String {
        let mainBundle = CFBundleGetMainBundle()
        if let idRef = CFBundleGetIdentifier(mainBundle) {
            return idRef as String
        }
        return "Fail"
    }

    // --- 2. Dict ---
    func getDictFromInfo() -> String {
        if let path = Bundle.main.path(forResource: "Info", ofType: "plist"),
           let dict = NSDictionary(contentsOfFile: path),
           let id = dict["CFBundleIdentifier"] as? String {
            return id
        }
        return "Fail"
    }

    // --- 3. fopen ---
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

    // --- 4. SecTask ---
    func getSecTaskSigningIdentifier() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "Fail" }
        if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
            return idRef as String
        }
        return "Unknown"
    }
    
    // --- 5. SecCode (新) ---
    func getSecCodeID() -> String {
        var code: SecCodeRef? = nil
        // kSecCSDefaultFlags = 0
        if SecCodeCopySelf(0, &code) == 0, let validCode = code {
            var info: CFDictionary? = nil
            // kSecCSRequirementInformation = 1 << 0
            if SecCodeCopySigningInformation(validCode, 1, &info) == 0, let validInfo = info as? [String: Any] {
                // kSecCodeInfoIdentifier = "identifier"
                if let id = validInfo["identifier"] as? String {
                    return id
                }
            }
        }
        return "SecCode Fail"
    }
    
    // --- 6. Audit Token (新) ---
    func getAuditTokenID() -> String {
        var token = audit_token_t_swift()
        var size = mach_msg_type_number_t(MemoryLayout<audit_token_t_swift>.size / 4) // size in integer_t
        
        let kTaskAuditToken = Int32(15) // TASK_AUDIT_TOKEN
        
        // 使用 withUnsafeMutablePointer 安全地转换结构体指针
        let result = withUnsafeMutablePointer(to: &token) { ptr -> Int32 in
            // 强转为 task_info 需要的 integer_t 指针
            let intPtr = ptr.withMemoryRebound(to: integer_t.self, capacity: Int(size)) { $0 }
            return task_info(mach_task_self_, kTaskAuditToken, intPtr, &size)
        }
        
        if result == 0 { // KERN_SUCCESS
            // 重新获取指针传递给 Security API
            return withUnsafePointer(to: &token) { ptr -> String in
                 guard let secTask = SecTaskCreateFromAuditToken(ptr) else { return "Token Invalid" }
                 if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
                     return idRef as String
                 }
                 return "Token No ID"
            }
        }
        return "Task Info Fail"
    }
    
    // --- 7. Mach-O Embedded Info.plist (新) ---
    func getMachOEmbeddedInfoID() -> String {
        // 1. 获取主二进制内存地址 (通过 dlsym 找 header)
        let RTLD_MAIN_ONLY = UnsafeMutableRawPointer(bitPattern: -5) // macOS/iOS constant
        // 尝试获取 header
        // 这里简化处理：直接读取文件，因为内存解析在 Swift 单文件里太复杂且容易 Crash
        // 我们读取 executablePath
        guard let path = Bundle.main.executablePath else { return "No Exec Path" }
        guard let file = fopen(path, "r") else { return "Open Exec Fail" }
        defer { fclose(file) }
        
        // 读取 Header
        var header = mach_header_64()
        if fread(&header, MemoryLayout<mach_header_64>.size, 1, file) != 1 { return "Read Header Fail" }
        
        // 必须是 64 位 Mach-O
        if header.magic != MH_MAGIC_64 { return "Not 64-bit" }
        
        // 遍历 Load Commands
        var cmdOffset = MemoryLayout<mach_header_64>.size
        var lc = load_command()
        
        for _ in 0..<header.ncmds {
            fseek(file, 0, SEEK_SET)
            fseek(file, Int(cmdOffset), SEEK_CUR)
            if fread(&lc, MemoryLayout<load_command>.size, 1, file) != 1 { break }
            
            // LC_SEGMENT_64 = 0x19
            if lc.cmd == 0x19 {
                // 读取 Segment Command
                fseek(file, 0, SEEK_SET)
                fseek(file, Int(cmdOffset), SEEK_CUR)
                var seg = segment_command_64()
                if fread(&seg, MemoryLayout<segment_command_64>.size, 1, file) != 1 { break }
                
                // 检查段名是否是 __TEXT
                let segName = withUnsafePointer(to: &seg.segname) {
                    $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                }
                
                if segName == "__TEXT" {
                    // 遍历 Sections
                    var sectOffset = cmdOffset + MemoryLayout<segment_command_64>.size
                    for _ in 0..<seg.nsects {
                        fseek(file, 0, SEEK_SET)
                        fseek(file, Int(sectOffset), SEEK_CUR)
                        var sect = section_64()
                        if fread(&sect, MemoryLayout<section_64>.size, 1, file) != 1 { break }
                        
                        let sectName = withUnsafePointer(to: &sect.sectname) {
                            $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                        }
                        
                        // 找到了内嵌的 Info.plist
                        if sectName == "__info_plist" {
                            // 读取 Section 数据
                            let size = Int(sect.size)
                            let offset = Int(sect.offset)
                            if size > 0 {
                                fseek(file, 0, SEEK_SET)
                                fseek(file, offset, SEEK_CUR)
                                var buffer = [CChar](repeating: 0, count: size + 1)
                                fread(&buffer, 1, size, file)
                                
                                // 尝试解析
                                let content = String(cString: buffer)
                                if let range = content.range(of: "CFBundleIdentifier") {
                                    let sub = content[range.upperBound...]
                                    if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                                        return String(sub[start.upperBound..<end.lowerBound])
                                    }
                                }
                                return "Parse Plist Fail"
                            }
                        }
                        sectOffset += MemoryLayout<section_64>.size
                    }
                }
            }
            cmdOffset += Int(lc.cmdsize)
        }
        
        return "Section Not Found"
    }

    // --- 8. Entitlements (新) ---
    func getEntitlementsAppID() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else { return "Fail" }
        // "application-identifier"
        let key = "application-identifier" as CFString
        if let value = SecTaskCopyValueForEntitlement(secTask, key, nil) as? String {
            return value
        }
        return "Not Found"
    }
    
    // --- 9. Provision ---
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
    
    // --- 10. Runtime Check ---
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
