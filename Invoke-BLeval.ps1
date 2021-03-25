#Triggers evaluation of all ConfigMgr compliance baselines 
#Modified from https://social.technet.microsoft.com/Forums/en-US/76afbba5-065e-4809-9720-024ea05d6cee/trigger-baseline-evaluation?forum=configmanagersdk

$ComputerName = "localhost"
$Baselines = Get-WmiObject -ComputerName $ComputerName -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration
#echo $baselines
ForEach ($Baseline in $Baselines){

    $name = $Baseline.Name
    $IsMachineTarget = $Baseline.IsMachineTarget
    $IsEnforced = $Baseline.IsEnforced
    $PolicyType = $Baseline.PolicyType
    $version = $Baseline.Version

    $MC = [WmiClass]"\\$ComputerName\root\ccm\dcm:SMS_DesiredConfiguration"

    $Method = "TriggerEvaluation"
    $InParams = $mc.psbase.GetMethodParameters($Method)
    $InParams.IsEnforced = $IsEnforced
    $InParams.IsMachineTarget = $IsMachineTarget
    $InParams.Name = $name
    $InParams.Version = $version
    $InParams.PolicyType = $PolicyType
    Write-Host $Baseline.DisplayName
    $inparams.PSBase.properties | select Name,Value | format-Table
    $R = $MC.InvokeMethod($Method, $InParams, $null)
    $R | Format-Table
}
