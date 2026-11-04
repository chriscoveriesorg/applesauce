-- User-run Finder acceptance for an already signed, mounted ASCF volume.
-- Finder must enumerate the restored file and report its original logical size.
-- The paired Python verifier independently authenticates the complete SHA-256.
-- The invoking Terminal may need an Apple Events / Automation permission grant.
on run argv
    if (count of argv) is not 3 then error "Usage: finder_readback.applescript MOUNT_DIR EXPECTED_NAME EXPECTED_BYTES"
    set mountPath to item 1 of argv as text
    set expectedName to item 2 of argv as text
    set expectedBytes to item 3 of argv as integer

    set mountedFolder to (POSIX file mountPath) as alias
    tell application "Finder"
        set visibleFiles to every file of mountedFolder
        if (count of visibleFiles) is not 1 then error "Finder did not enumerate exactly one restored file on ASCF volume."
        set restoredItem to item 1 of visibleFiles
        set actualName to name of restoredItem as text
        set actualBytes to size of restoredItem
        set finderVersion to version as text
    end tell

    if actualName is not expectedName then error "Finder restored filename differs: " & actualName
    if actualBytes is missing value then error "Finder could not obtain logical file size."
    if actualBytes is not expectedBytes then error "Finder restored logical file size differs: " & (actualBytes as text)
    return "FINDER_PASS" & tab & actualName & tab & (actualBytes as text) & tab & finderVersion
end run
