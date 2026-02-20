import Foundation
import SSHAgentLib

let args = Array(CommandLine.arguments.dropFirst())

guard let command = args.first else {
    printUsage()
    exit(1)
}

let commandArgs = Array(args.dropFirst())

do {
    switch command {
    case "setup":
        try commandSetup(args: commandArgs)
    case "generate":
        try commandGenerate(args: commandArgs)
    case "list":
        try commandList(args: commandArgs)
    case "export":
        try commandExport(args: commandArgs)
    case "delete":
        try commandDelete(args: commandArgs)
    case "help", "--help", "-h":
        printUsage()
    default:
        printStderr("Unknown command: \(command)")
        printUsage()
        exit(1)
    }
} catch {
    printStderr("Error: \(error)")
    exit(1)
}
