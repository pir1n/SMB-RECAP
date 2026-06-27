param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "stop")]
    [string]$Action,

    [string]$Output
)

$ErrorActionPreference = "Stop"

if ($Action -eq "start") {
    pktmon stop
    pktmon filter remove
    pktmon filter add -p 445
    pktmon start --capture --pkt-size 0
    exit $LASTEXITCODE
}

if ($Action -eq "stop") {
    if (-not $Output) {
        throw "-Output is required for stop"
    }
    pktmon stop
    pktmon pcapng PktMon.etl -o $Output
    exit $LASTEXITCODE
}
