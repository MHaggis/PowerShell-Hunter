. .\Invoke-ADThreatSimulation.ps1

$params = @{}
foreach($key in $PSBoundParameters.Keys) {
    $params[$key] = $PSBoundParameters[$key]
}
Invoke-ADThreatSimulation @params 