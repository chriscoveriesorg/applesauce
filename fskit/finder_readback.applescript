-- User-run Finder acceptance for an already signed, mounted ASCF volume.
-- Finder must enumerate the restored file, report its logical size, and copy
-- the synthetic mounted data into a fresh local evidence directory.
-- The invoking shell verifies the copy's full SHA-256 against cleartext.
-- The invoking Terminal may need an Apple Events / Automation permission grant.
on run argv
    if (count of argv) is not 4 then error "Usage: finder_readback.applescript MOUNT_DIR EXPECTED_NAME EXPECTED_BYTES COPY_DIR"
    set mountPath to item 1 of argv as text
    set expectedName to item 2 of argv as text
    set expectedBytes to item 3 of argv as integer
    set copyDirectory to item 4 of argv as text

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

    -- The shell creates COPY_DIR with mktemp. Never ask Finder to overwrite
    -- an existing file and never copy anything into the mounted filesystem.
    set destinationFolder to (POSIX file copyDirectory) as alias
    tell application "Finder"
        if (count of every item of destinationFolder) is not 0 then error "Finder readback destination is not empty."
        set copiedItem to duplicate restoredItem to destinationFolder
        if (name of copiedItem as text) is not expectedName then error "Finder returned an unexpected copied item."
    end tell
    return "FINDER_COPY_PASS" & tab & actualName & tab & (actualBytes as text) & tab & finderVersion
end run
