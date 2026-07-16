param(
    [int]$DiskNumber = 1,
    [char]$DriveLetter = 'R'
)

$ErrorActionPreference = 'Stop'

$disk = Get-Disk -Number $DiskNumber
$minimumSize = 30GB
$maximumSize = 34GB
if ($disk.IsBoot -or $disk.IsSystem) {
    throw "Refusing to modify boot/system Disk $DiskNumber"
}
if ($disk.PartitionStyle -ne 'RAW') {
    throw "Refusing to modify Disk $DiskNumber because it is not RAW"
}
if ($disk.Size -lt $minimumSize -or $disk.Size -gt $maximumSize) {
    throw "Refusing Disk $DiskNumber because its size is outside the expected 30-34 GB range"
}
if (Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue) {
    throw "Refusing to reuse occupied drive letter $DriveLetter"
}

Set-Disk -Number $DiskNumber -IsOffline $false
Set-Disk -Number $DiskNumber -IsReadOnly $false
Initialize-Disk -Number $DiskNumber -PartitionStyle GPT
$partition = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -DriveLetter $DriveLetter
$volume = Format-Volume -Partition $partition -FileSystem ReFS -NewFileSystemLabel 'TZAP_REFS_TEST' -Force -Confirm:$false

$volume | Select-Object DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining
