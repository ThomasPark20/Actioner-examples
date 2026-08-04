rule Malware_CountLoader_DOUBLECUP
{
    meta:
        description = "Detects CountLoader malware associated with DOUBLECUP campaigns based on persistence task names and PE masquerading artifacts"
        author = "Actioner"
        date = "2026-08-04"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "bdf28e611d77362c40a0445655a35943c03accf21bb9a5af755da7eac5ea5e40"
        severity = "high"

    strings:
        $task1 = "GoogleUpdateService{" ascii wide
        $task2 = "MSEdgeUpdateService{" ascii wide
        $irm = "irm" ascii wide fullword
        $iex = "iex" ascii wide fullword
        $bypass = "-ep bypass" ascii wide nocase
        $wallet_check1 = "MetaMask" ascii wide
        $wallet_check2 = "Phantom" ascii wide
        $wallet_check3 = "Binance" ascii wide
        $signal = "Signal" ascii wide fullword
        $cross_compile = "source\\repos\\TestApp\\Mac_C" ascii

    condition:
        filesize < 10MB and
        (
            (1 of ($task*) and ($irm or $iex) and $bypass) or
            ($cross_compile) or
            (1 of ($task*) and 2 of ($wallet_check*)) or
            ($signal and 2 of ($wallet_check*) and 1 of ($task*))
        )
}
