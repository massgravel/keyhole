# if doesnt work then try F0C62012-2CEF-4831-B1F7-930682874C86 :3c

[Windows.Security.Authentication.OnlineId.OnlineIdSystemAuthenticatorForUser,Windows.Security.Authentication.OnlineId,ContentType=WindowsRuntime] | Out-Null
[Windows.Security.Authentication.OnlineId.OnlineIdSystemTicketResult,Windows.Security.Authentication.OnlineId,ContentType=WindowsRuntime] | Out-Null

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
Function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}
Function AwaitAction($WinRtAction) {
    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]
    $netTask = $asTask.Invoke($null, @($WinRtAction))
    $netTask.Wait(-1) | Out-Null
}

$auth = [Windows.Security.Authentication.OnlineId.OnlineIdSystemAuthenticator]::Default
$req = New-Object Windows.Security.Authentication.OnlineId.OnlineIdServiceTicketRequest("service::www.microsoft.com::MBI_SSL")
$auth.ApplicationId = [System.Guid]::New("D6D5A677-0872-4AB0-9442-BB792FCE85C5")
$res = Await $auth.GetTicketAsync($req) ([Windows.Security.Authentication.OnlineId.OnlineIdSystemTicketResult])
Write-Output $res.Identity.Id
Write-Output $res.Identity.Ticket.Value