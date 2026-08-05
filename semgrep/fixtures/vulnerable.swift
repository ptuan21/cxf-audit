import Foundation

func extractUnsafe(archive: Archive, destDir: URL) {
    for entry in archive {
        let path = entry.path
        // ruleid: zip-slip-taint-swift
        let destinationURL = destDir.appendingPathComponent(path)
        try? archive.extract(entry, to: destinationURL)
    }
}

func extractSafe(archive: Archive, destDir: URL) {
    for entry in archive {
        let path = entry.path
        if path.contains("..") {
            continue
        }
        // ok: zip-slip-taint-swift
        let destinationURL = destDir.appendingPathComponent(path)
        try? archive.extract(entry, to: destinationURL)
    }
}

func writeLog(destDir: URL) {
    // ok: zip-slip-taint-swift
    let logURL = destDir.appendingPathComponent("app.log")
}
