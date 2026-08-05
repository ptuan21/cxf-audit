import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

fun extractUnsafe(zis: ZipInputStream, destDir: File) {
    var entry = zis.nextEntry
    while (entry != null) {
        // ruleid: zip-slip-taint-kotlin
        val outFile = File(destDir, entry.name)
        FileOutputStream(outFile).use { fos -> zis.copyTo(fos) }
        entry = zis.nextEntry
    }
}

fun extractSafe(zis: ZipInputStream, destDir: File) {
    var entry = zis.nextEntry
    while (entry != null) {
        val name = entry.name
        if (name.contains("..")) {
            entry = zis.nextEntry
            continue
        }
        // ok: zip-slip-taint-kotlin
        val outFile = File(destDir, name)
        FileOutputStream(outFile).use { fos -> zis.copyTo(fos) }
        entry = zis.nextEntry
    }
}

fun writeLog(destDir: File) {
    // ok: zip-slip-taint-kotlin
    val outFile = File(destDir, "app.log")
}
