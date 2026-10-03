import AppKit

let application = NSApplication.shared
application.setActivationPolicy(.accessory)
application.finishLaunching()
let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/keyward")
let log = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Logs/keyward/activity.jsonl")

func service(_ action: String) -> (Bool, String) {
    let process = Process()
    process.executableURL = helper
    process.arguments = ["service", action]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    let input = Pipe()
    process.standardInput = input
    do {
        try process.run()
        // The status window already warned before the user chose Disable.
        if action == "uninstall" {
            input.fileHandleForWriting.write(Data("yes\n".utf8))
        }
        input.fileHandleForWriting.closeFile()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus == 0, String(decoding: data, as: UTF8.self))
    } catch {
        return (false, "Could not check the daemon: \(error.localizedDescription)")
    }
}

while true {
    let (_, status) = service("status")
    let running = status.contains("daemon is running")
    let alert = NSAlert()
    alert.messageText = "Keyward by Veilux"
    alert.informativeText = status.trimmingCharacters(in: .whitespacesAndNewlines)
        + "\n\nActivity logs record request names and outcomes. Secret values are never logged. History is kept for 30 days, capped at 50 MB by default."
    if running {
        alert.informativeText += "\n\nWarning: disabling startup stops the daemon; cap:// references will not resolve while it is stopped. Before uninstalling or deleting Keyward, run keyward restore <file>... in Terminal if you want secrets returned to your files (for example: keyward restore ~/.zshrc .env). Restored files contain plaintext secrets again. Keychain entries are kept."
    }
    alert.icon = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "Keyward")
    alert.addButton(withTitle: "Done")
    alert.addButton(withTitle: "View Activity Log")
    alert.addButton(withTitle: running ? "Disable Automatic Startup" : "Enable Automatic Startup")
    application.activate(ignoringOtherApps: true)
    switch alert.runModal() {
    case .alertSecondButtonReturn:
        NSWorkspace.shared.open(log)
        exit(0)
    case .alertThirdButtonReturn:
        let (ok, message) = service(running ? "uninstall" : "install")
        if !ok {
            let error = NSAlert()
            error.messageText = "Keyward could not update automatic startup"
            error.informativeText = message
            error.runModal()
        }
    default:
        exit(0)
    }
}
