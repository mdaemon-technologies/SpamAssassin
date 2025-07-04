# Multi-threaded SPAMC Email Processing Script with Enhanced Rule Tracking

<#
.SYNOPSIS
Multi-threaded email spam analysis using SpamAssassin's SPAMC protocol with detailed rule tracking.

.DESCRIPTION
This script processes .msg email files through SpamAssassin's spamd daemon using the SPAMC protocol.
It provides multi-threaded processing for improved performance and detailed analysis of triggered spam rules.

.PARAMETER MSGPath
Path to directory containing .msg files to process.

.PARAMETER MaxConcurrentJobs
Maximum number of simultaneous processing threads (1-50).
Higher values increase speed but use more system resources.
Default: 5

.PARAMETER RemoteHost
IP address or hostname of the SpamAssassin spamd server.
Default: "127.0.0.1" (localhost)

.PARAMETER Port
TCP port number for spamd connection (1-65535).
Default: 783 (standard SPAMC port)

.PARAMETER EnableDebug
Enables detailed debug output showing processing steps and timing information.
Useful for troubleshooting connection or parsing issues.

.PARAMETER LogResponses
Saves complete SPAMD server responses to a log file for analysis.
Helpful for debugging rule parsing or server communication issues.

.PARAMETER LogPath
Directory path for log files and CSV exports.
If not specified, uses current directory for logs.

.PARAMETER ExportCSV
Exports detailed results and rule statistics to CSV files with timestamp.
Creates two files: SpamResults_[timestamp].csv and RuleStats_[timestamp].csv

.EXAMPLE
.\MultiThreadedSpamCheck.ps1 -MSGPath "C:\Email\Inbox" -MaxConcurrentJobs 10 -ExportCSV
Processes files from custom path with 10 threads and exports results to CSV.

.EXAMPLE
.\MultiThreadedSpamCheck.ps1 -RemoteHost "spam-server.local" -Port 1783 -EnableDebug -LogResponses
Connects to remote spamd server with debug logging enabled.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$MSGPath = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 50)]
    [int]$MaxConcurrentJobs = 5,
    
    [Parameter(Mandatory=$false)]
    [string]$RemoteHost = "127.0.0.1",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 65535)]
    [int]$Port = 783,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableDebug = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$LogResponses = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV = $false
)

$ScriptBlock = {
    param($MSGFile, $RemoteHost, $Port, $GetResponseThreadedFunction, $ProcessBufferThreadedFunction, $EnableDebug, $LogResponses, $LogPath)

    # Start stopwatch as the very first operation
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Import functions into runspace only once
    if (-not (Get-Command GetResponseThreaded -ErrorAction SilentlyContinue)) {
        Set-Item -Path function:GetResponseThreaded -Value ([ScriptBlock]::Create($GetResponseThreadedFunction)) -Force
    }
    if (-not (Get-Command ProcessBufferThreaded -ErrorAction SilentlyContinue)) {
        Set-Item -Path function:ProcessBufferThreaded -Value ([ScriptBlock]::Create($ProcessBufferThreadedFunction)) -Force
    }

    $result = @{
        FileName = $MSGFile.Name
        FullPath = $MSGFile.FullName
        Success = $false
        Error = $null
        MSGID = ""
        Result = ""
        Score = ""
        Threshold = ""
        ProcessingTime = 0
        RuleHits = @()
        RuleCount = 0
        TopRules = ""
        DebugInfo = ""
        ThreadLog = @()
    }

    try {
        if ($EnableDebug) { $result.ThreadLog += "Processing: $($MSGFile.Name)" }

        $TCPConnection = [System.Net.Sockets.TcpClient]::new($RemoteHost, $Port)
        $NetStream = $TCPConnection.GetStream()
        $Writer = [System.IO.StreamWriter]::new($NetStream)
        $MSG = Get-Content -Path $MSGFile.FullName -Raw -Encoding UTF8
        $MSGBytes = [System.Text.Encoding]::UTF8.GetBytes($MSG)
        $Length = $MSGBytes.Length

        if ($EnableDebug) { $result.ThreadLog += "  Sending SPAMC REPORT request for $($MSGFile.Name) - Length: $Length bytes" }
        $Writer.WriteLine("REPORT SPAMC/1.3")
        $Writer.WriteLine("Content-length: $Length")
        $Writer.WriteLine("")
        $Writer.Flush()
        $NetStream.Write($MSGBytes, 0, $MSGBytes.Length)
        $NetStream.Flush()
        if ($EnableDebug) { $result.ThreadLog += "  Request sent, waiting for response..." }

        $responseStartTime = Get-Date
        $response = GetResponseThreaded $NetStream $EnableDebug $result
        $responseTime = ((Get-Date) - $responseStartTime).TotalMilliseconds
        $result.ThreadLog += "  Response received in $([math]::Round($responseTime, 0)) ms"

        if ($response) {
            if ($EnableDebug) { $result.ThreadLog += "  Processing response ($($response.Length) chars)..." }
            if ($LogResponses) {
                $logFile = if ($LogPath) { $LogPath } else { Join-Path $env:TEMP "spamc_responses.log" }
                $logEntry = "=== SPAMC RESPONSE for $($MSGFile.Name) at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===`nLength: $($response.Length) characters`nRaw Response:`n$response`n=== END RESPONSE ===`n"
                try {
                    Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
                    $result.ThreadLog += "  Response logged to: $logFile"
                } catch {
                    $result.ThreadLog += "  Failed to log response: $($_.Exception.Message)"
                }
            }
            if ($EnableDebug) {
                $result.ThreadLog += "  --- SPAMC RESPONSE PREVIEW ---"
                $result.ThreadLog += "  " + ($response.Substring(0, [Math]::Min(1000, $response.Length)) + ($(if ($response.Length -gt 1000) { "..." } else { "" })))
                $result.ThreadLog += "  --- END PREVIEW ---"
            }
            $processed = ProcessBufferThreaded $response $EnableDebug $result
            foreach ($k in $processed.Keys) { $result[$k] = $processed[$k] }
            $result.Success = $true
        } else {
            $result.ThreadLog += "  ✗ No response received from server"
            $result.Error = "No response from spamd"
        }

        # Cleanup
        foreach ($obj in @($Writer, $NetStream, $TCPConnection)) { try { if ($obj) { $obj.Close(); $obj.Dispose() } } catch {} }
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Warning "Error processing $($MSGFile.Name): $($_.Exception.Message)"
        foreach ($obj in @($Writer, $NetStream, $TCPConnection)) { try { if ($obj) { $obj.Close(); $obj.Dispose() } } catch {} }
    }
    finally {
        $stopwatch.Stop()
        $result.ProcessingTime = $stopwatch.ElapsedMilliseconds
    }
    return [PSCustomObject]$result
}

function GetResponseThreaded($NetStream, $EnableDebug = $false, $result = $null) {
    $buffer = New-Object System.Byte[] 4096
    $encoding = [System.Text.Encoding]::ASCII
    $outputBuffer = ""
    $headerComplete = $false
    $contentLength = 0
    $bodyLength = 0
    $readCount = 0
    $totalBytesRead = 0
    $NetStream.ReadTimeout = 60000
    $startTime = Get-Date
    if ($EnableDebug -and $result) { $result.ThreadLog += "    [DEBUG] Starting response read at $($startTime.ToString('HH:mm:ss.fff'))" }
    do {
        $foundmore = $false
        $readStartTime = Get-Date
        try {
            $bytesRead = $NetStream.Read($buffer, 0, 4096)
            $readCount++; $totalBytesRead += $bytesRead
            if ($EnableDebug -and $result) { $result.ThreadLog += "    [DEBUG] Read #$readCount`: $bytesRead bytes" }
            if ($bytesRead -gt 0) {
                $foundmore = $true
                $chunk = $encoding.GetString($buffer, 0, $bytesRead)
                $outputBuffer += $chunk
                if (-not $headerComplete -and $outputBuffer -match "`r`n`r`n") {
                    $headerComplete = $true
                    if ($outputBuffer -match "Content-Length:\s*(\d+)") { $contentLength = [int]$Matches[1] }
                    $headerEndIndex = $outputBuffer.IndexOf("`r`n`r`n") + 4
                    $bodyLength = $outputBuffer.Length - $headerEndIndex
                } elseif ($headerComplete) {
                    $bodyLength += $bytesRead
                }
            }
        } catch { $foundmore = $false }
        if ($headerComplete) {
            if ($contentLength -gt 0 -and $bodyLength -ge $contentLength) { break }
            elseif ($contentLength -eq 0 -and $outputBuffer -match "SPAMD/[0-9.]+ \d+ [A-Z_]+") {
                Start-Sleep -Milliseconds 50
                try {
                    $NetStream.ReadTimeout = 1000
                    $finalRead = $NetStream.Read($buffer, 0, 4096)
                    if ($finalRead -gt 0) { $outputBuffer += $encoding.GetString($buffer, 0, $finalRead); $totalBytesRead += $finalRead } else { break }
                } catch { break }
            }
        }
        if ($outputBuffer.Length -gt 500000) { break }
    } while ($foundmore)
    return $outputBuffer
}

function ProcessBufferThreaded($outputBuffer, $EnableDebug = $false, $result = $null) {
    $parts = $outputBuffer -split "`r`n`r`n", 2
    $headers = $parts[0]
    $body = if ($parts.Length -gt 1) { $parts[1] } else { "" }
    $parseResult = @{
        MSGID = ""
        Result = ""
        Score = ""
        Threshold = ""
        RuleHits = @()
        RuleCount = 0
        TopRules = ""
        DebugInfo = ""
    }
    
    if ($outputBuffer -match "Message-Id:\s*(.*)" -or $outputBuffer -match "Message-ID:\s*(.*)") { 
        $parseResult.MSGID = $Matches[1].Trim() 
    }
    
    if ($headers -match "Spam:\s*(.*)") {
        $spamLine = $Matches[1].Trim()
        if ($spamLine -match "([^;]+);\s*([\d.-]+)\s*/\s*([\d.-]+)") {
            $parseResult.Result = $Matches[1].Trim()
            $parseResult.Score = $Matches[2].Trim()
            $parseResult.Threshold = $Matches[3].Trim()
        }
    }
    
    if ($body -and $body.Length -gt 0) {
        # Use substring approach instead of complex regex
        $analysisMarker = "Content analysis details:"
        $analysisStart = $body.IndexOf($analysisMarker)
        
        if ($analysisStart -ge 0) {
            # Find the header line with "pts rule name description"
            $headerMarker = "pts rule name"
            $headerStart = $body.IndexOf($headerMarker, $analysisStart)
            
            if ($headerStart -ge 0) {
                # Find the line after the dashes (the actual rules start)
                $bodyAfterHeader = $body.Substring($headerStart)
                $lines = $bodyAfterHeader -split "`r?`n"
                
                # Find where the actual rule data starts (after the dashes)
                $ruleStartIndex = -1
                for ($i = 0; $i -lt $lines.Length; $i++) {
                    if ($lines[$i] -match "^[\s-]+$") {
                        $ruleStartIndex = $i + 1
                        break
                    }
                }
                
                if ($ruleStartIndex -ge 0 -and $ruleStartIndex -lt $lines.Length) {
                    $detailedRules = @()
                    # Process rule lines
                    for ($i = $ruleStartIndex; $i -lt $lines.Length; $i++) {
                        $line = $lines[$i].Trim()
                        
                        # Stop if we hit an empty line or end of rules
                        if ([string]::IsNullOrWhiteSpace($line)) {
                            break
                        }
                        
                        # Parse the rule line: score, rule name, description
                        if ($line -match "^\s*([\d.-]+)\s+([A-Z_][A-Z0-9_]*)\s+(.*)$") {
                            $score = [decimal]$Matches[1]
                            $ruleName = $Matches[2].Trim()
                            $description = $Matches[3].Trim()
                            
                            $detailedRules += [PSCustomObject]@{ 
                                Score = $score
                                Rule = $ruleName
                                Description = $description 
                            }
                        }
                    }
                    
                    if ($detailedRules.Count -gt 0) {
                        $sortedRules = $detailedRules | Sort-Object Score -Descending
                        $parseResult.RuleHits = $sortedRules
                        $parseResult.RuleCount = $detailedRules.Count
                        $parseResult.TopRules = ($sortedRules | Select-Object -First 5 | ForEach-Object { "$($_.Rule)($($_.Score))" }) -join ", "
                    }
                }
            }
        }
    }
    
    # Fallback parsing
    if ([string]::IsNullOrEmpty($parseResult.Score) -and $headers -match "X-Spam-Score:\s*([\d.-]+)") { 
        $parseResult.Score = $Matches[1] 
    }
    if ([string]::IsNullOrEmpty($parseResult.Threshold) -and $headers -match "X-Spam-(?:Level|Threshold):\s*([\d.-]+)") { 
        $parseResult.Threshold = $Matches[1] 
    }
    if ([string]::IsNullOrEmpty($parseResult.Result) -and $headers -match "SPAMD/[\d.]+\s+(\d+)\s+(.*)") {
        $code = $Matches[1]; $message = $Matches[2].Trim()
        if ($code -ne "0") { $parseResult.Result = "Error: Code $code - $message" }
    }
    
    return $parseResult
}

# ---[ Utility Functions ]---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info",
        [ConsoleColor]$Color = [ConsoleColor]::White
    )

    # Use script scope to access the EnableDebug parameter
    if (-not $script:EnableDebug -and $Level -eq "Debug") { 
        return 
    }

    Write-Host "$Message" -ForegroundColor $Color
}

function Get-ExportDirectory {
    param([string]$LogPath)
    if ($LogPath) { return $LogPath }
    return (Get-Location)
}

function Get-ActualLogPath {
    param([string]$LogPath)
    if ($LogPath) { return (Join-Path $LogPath "spamc_responses.log") }
    return (Join-Path (Get-Location) "spamc_responses.log")
}

function Get-MSGFiles {
    param([string]$MSGPath)
    $files = Get-ChildItem -Path $MSGPath -Filter *.msg -ErrorAction SilentlyContinue
    return $files
}

function New-ThreadSafeQueue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [psobject]$InputObject
    )

    begin {
        # Initialize the queue once before processing any items from the pipeline.
        $queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    }

    process {
        # For each object piped to the function, add it to the queue.
        if ($null -ne $InputObject) {
            $queue.Enqueue($InputObject)
        }
    }

    end {
        # After all items are processed, return the fully populated queue.
        # Use the comma operator to prevent PowerShell from unrolling the queue's contents.
        return ,$queue
    }
}

function New-RunspacePool {
    param([int]$MaxConcurrentJobs)
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrentJobs)
    $pool.Open()
    return $pool
}

function Submit-Job {
    param(
        $ScriptBlock, $MSGFile, $RemoteHost, $Port,
        $GetResponseThreadedFunction, $ProcessBufferThreadedFunction,
        $EnableDebug, $LogResponses, $LogPath, $RunspacePool
    )
    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    [void]$PowerShell.AddScript($ScriptBlock)
    [void]$PowerShell.AddParameter("MSGFile", $MSGFile)
    [void]$PowerShell.AddParameter("RemoteHost", $RemoteHost)
    [void]$PowerShell.AddParameter("Port", $Port)
    [void]$PowerShell.AddParameter("GetResponseThreadedFunction", $GetResponseThreadedFunction)
    [void]$PowerShell.AddParameter("ProcessBufferThreadedFunction", $ProcessBufferThreadedFunction)
    [void]$PowerShell.AddParameter("EnableDebug", $EnableDebug)
    [void]$PowerShell.AddParameter("LogResponses", $LogResponses)
    [void]$PowerShell.AddParameter("LogPath", $LogPath)
    return @{
        PowerShell = $PowerShell
        Handle = $PowerShell.BeginInvoke()
        File = $MSGFile.Name
        SubmitTime = Get-Date
    }
}

function Collect-CompletedJobs {
    param($Jobs, [ref]$Results, [ref]$TotalProcessed, $EnableDebug, $TotalFileCount)
    $CompletedJobs = $Jobs | Where-Object { $_.Handle.IsCompleted }
    $RemainingJobs = @()
    foreach ($Job in $Jobs) {
        if ($Job.Handle.IsCompleted) {
            $ResultData = $null
            try {
                $ResultData = $Job.PowerShell.EndInvoke($Job.Handle)
                if ($ResultData) {
                    [void]$Results.Value.Add($ResultData)
                } else {
                    $ResultData = [PSCustomObject]@{
                        FileName = $Job.File; Success = $false; Error = "Job returned null result"; ProcessingTime = 0; RuleHits = @()
                    }
                    [void]$Results.Value.Add($ResultData)
                }
            } catch {
                $ResultData = [PSCustomObject]@{
                    FileName = $Job.File; Success = $false; Error = "Job failed: $($_.Exception.Message)"; ProcessingTime = 0; RuleHits = @()
                }
                [void]$Results.Value.Add($ResultData)
            } finally {
                $Job.PowerShell.Dispose()
                $TotalProcessed.Value++
                Write-Log "Completed ($($TotalProcessed.Value)/$TotalFileCount): $($Job.File)" "Info" "Gray"
                if ($ResultData) {
                    if ($EnableDebug -and $ResultData.ThreadLog) {
                        $ResultData.ThreadLog | ForEach-Object { Write-Log $_ "Debug" "Gray" }
                    }
                    if ($ResultData.Success) {
                        $statusMsg = "Result: '$($ResultData.Result)', Score: '$($ResultData.Score)'"
                        if ($ResultData.RuleCount -gt 0) {
                            $statusMsg += ", Rules: $($ResultData.RuleCount)"
                        }
                        Write-Log "  ✓ $statusMsg" "Info" "Green"
                        if ($ResultData.RuleHits.Count -gt 0) {
                            Write-Log "    Rules triggered:" "Info" "Cyan"
                            $ResultData.RuleHits | ForEach-Object {
                                Write-Log "      ($($_.Score)) $($_.Rule): $($_.Description)" "Info" "Cyan"
                            }
                        }
                    } else {
                        Write-Log "  ✗ Failed - Error: $($ResultData.Error)" "Error" "Red"
                    }
                }
            }
        } else {
            $RemainingJobs += $Job
        }
    }
    return $RemainingJobs
}

function New-Configuration {
    param(
        [string]$MSGPath,
        [int]$MaxConcurrentJobs,
        [string]$RemoteHost,
        [int]$Port,
        [bool]$EnableDebug,
        [bool]$LogResponses,
        [string]$LogPath,
        [bool]$ExportCSV
    )

    return [PSCustomObject]@{
        MSGPath = $MSGPath
        MaxConcurrentJobs = $MaxConcurrentJobs
        RemoteHost = $RemoteHost
        Port = $Port
        EnableDebug = $EnableDebug
        LogResponses = $LogResponses
        LogPath = $LogPath
        ExportCSV = $ExportCSV
    }
}

function Show-Banner {
    param($config)
    Write-Log "=== Multi-threaded SPAMC Email Processor with Rule Tracking ===" "Info" "Cyan"
    Write-Log "Path: $($config.MSGPath)" "Info" "White"
    Write-Log "Host: $($config.RemoteHost):$($config.Port)" "Info" "White"
    Write-Log "Max Concurrent Jobs: $($config.MaxConcurrentJobs)" "Info" "White"
    if($config.EnableDebug) { Write-Log "Debug Mode: Enabled" "Info" "Yellow" }
    if($config.LogResponses) { Write-Log "Response Logging: Enabled -> $(Get-ActualLogPath $config.LogPath)" "Info" "Yellow" }
    if($config.ExportCSV) { Write-Log "CSV Export: Enabled -> $(Get-ExportDirectory $config.LogPath)" "Info" "Yellow" }
    Write-Log "" "Info" "White"
}

function Invoke-SpamCheck {
    param($config, $ScriptBlock)
    
    $GetResponseThreadedFunction = ${function:GetResponseThreaded}.ToString()
    $ProcessBufferThreadedFunction = ${function:ProcessBufferThreaded}.ToString()

    $AllMSGFiles = Get-MSGFiles $config.MSGPath

    if(-not $AllMSGFiles -or $AllMSGFiles.Count -eq 0) {
        Write-Log "No .msg files found in $($config.MSGPath)" "Warn" "Yellow"
        Write-Log "Please check the path and ensure .msg files exist." "Info" "White"
        return
    }

    $TotalFileCount = $AllMSGFiles.Count
    Write-Log "Found $TotalFileCount MSG files to process" "Info" "Green"

    $FileQueue = $AllMSGFiles | New-ThreadSafeQueue

    $RunspacePool = New-RunspacePool $config.MaxConcurrentJobs

    $Jobs = @()
    $Results = [System.Collections.ArrayList]::new()
    $TotalProcessed = 0

    try {
        while($TotalProcessed -lt $TotalFileCount) {
            while ($Jobs.Count -lt $config.MaxConcurrentJobs -and -not $FileQueue.IsEmpty) {
                $MSGFile = $null
                if ($FileQueue.TryDequeue([ref]$MSGFile)) {
                    $Job = Submit-Job $ScriptBlock $MSGFile $config.RemoteHost $config.Port $GetResponseThreadedFunction $ProcessBufferThreadedFunction $config.EnableDebug $config.LogResponses $config.LogPath $RunspacePool
                    $Jobs += $Job
                    if ($config.EnableDebug) { Write-Log "Submitted job for: $($MSGFile.Name)" "Debug" "Gray" }
                }
            }
            if ($Jobs.Count -gt 0) {
                $waitHandles = $Jobs.Handle | ForEach-Object { $_.AsyncWaitHandle }
                if ($waitHandles.Count -gt 0) {
                    [void][System.Threading.WaitHandle]::WaitAny($waitHandles, 60000)
                }
            }
            $refResults = [ref]$Results
            $refTotalProcessed = [ref]$TotalProcessed
            $Jobs = Collect-CompletedJobs $Jobs $refResults $refTotalProcessed $config.EnableDebug $TotalFileCount
            if ($Jobs.Count -eq 0 -and $FileQueue.IsEmpty) { break }
        }
    }
    finally {
        if($RunspacePool) {
            $RunspacePool.Close()
            $RunspacePool.Dispose()
        }
    }
    return $Results
}

function Get-RuleStatistics {
    param($FinalResults)

    $successfulResults = $FinalResults | Where-Object { $_.Success -and $_.RuleHits }
    $allRuleStats = @{}
    $messagesWithRules = 0
    
    foreach($result in $successfulResults) {
        if($result.RuleHits -and $result.RuleHits.Count -gt 0) {
            $messagesWithRules++
            foreach($rule in $result.RuleHits) {
                if(-not $allRuleStats.ContainsKey($rule.Rule)) {
                    $allRuleStats[$rule.Rule] = @{
                        Count = 0
                        TotalScore = 0
                        Score = $rule.Score
                        Description = $rule.Description
                    }
                }
                $allRuleStats[$rule.Rule].Count++
                $allRuleStats[$rule.Rule].TotalScore += $rule.Score
            }
        }
    }
    
    return [PSCustomObject]@{
        AllRuleStats = $allRuleStats
        MessagesWithRules = $messagesWithRules
        TotalMessages = $successfulResults.Count
    }
}

function Show-Results {
    param($FinalResults, $EnableDebug, $RuleStats)

    Write-Log "`n=== PROCESSING RESULTS ===" "Info" "Cyan"
    
    $displayColumns = @("FileName", "Success", "Result", "Score", "RuleCount", "ProcessingTime", "TopRules")
    if($EnableDebug) {
        $displayColumns += "DebugInfo"
    }
    
    $FinalResults | Format-Table $displayColumns -AutoSize
    
    Write-Log "`n=== SPAM RULE ANALYSIS ===" "Info" "Cyan"
    
    if($RuleStats.AllRuleStats.Count -gt 0) {
        Write-Log "Messages processed: $($RuleStats.TotalMessages)" "Info" "White"
        Write-Log "Messages with rules: $($RuleStats.MessagesWithRules)" "Info" "White"
        Write-Log "Unique rules found: $($RuleStats.AllRuleStats.Count)" "Info" "White"
        
        Write-Log "`nTop 25 Triggered Rules:" "Info" "White"
        $RuleStats.AllRuleStats.GetEnumerator() | 
            Sort-Object { $_.Value.Count } -Descending | 
            Select-Object -First 25 | 
            ForEach-Object {
                [PSCustomObject]@{
                    Rule = $_.Key
                    HitCount = $_.Value.Count
                    Frequency = "{0:P1}" -f ($_.Value.Count / $RuleStats.MessagesWithRules)
                    Score = [math]::Round($_.Value.Score, 2)
                    Description = $_.Value.Description
                }
            } |
            Format-Table Rule, HitCount, Frequency, Score, Description -AutoSize
            
        Write-Log "`nTop 25 Highest Scoring Rules:" "Info" "White"
        $RuleStats.AllRuleStats.GetEnumerator() | 
            Sort-Object { $_.Value.Score } -Descending | 
            Select-Object -First 25 | 
            ForEach-Object {
                [PSCustomObject]@{
                    Rule = $_.Key
                    Score = [math]::Round($_.Value.Score, 2)
                    HitCount = $_.Value.Count
                    Description = $_.Value.Description
                }
            } |
            Format-Table Rule, Score, HitCount, Description -AutoSize
    } else {
        Write-Log "No SpamAssassin rules were found in the processed messages." "Warn" "Yellow"
        if($EnableDebug) {
            Write-Log "Enable debug mode with -EnableDebug to see parsing details." "Info" "Yellow"
        }
    }
}

function Export-ResultsToCsv {
    param($config, $FinalResults, $RuleStats)

    if(-not $config.ExportCSV) {
        Write-Log "`nCSV export disabled. Use -ExportCSV to create result files." "Info" "Gray"
        return
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportDir = if($config.LogPath) { $config.LogPath } else { Get-Location }
    
    # Export main results (excluding RuleHits to keep it clean)
    $csvPath = Join-Path $exportDir "SpamResults_$timestamp.csv"
    if ($FinalResults -and $FinalResults.Count -gt 0) {
        $FinalResults | Select-Object * -ExcludeProperty RuleHits | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "`nDetailed results exported to: $csvPath" "Info" "Green"
    } else {
        Write-Log "`nNo results to export to CSV." "Warn" "Yellow"
    }
    
    # Export detailed rule hits for each message
    $allRulesPath = Join-Path $exportDir "AllRuleHits_$timestamp.csv"
    $allRuleHits = @()
    
    foreach ($result in $FinalResults) {
        if ($result.Success -and $result.RuleHits -and $result.RuleHits.Count -gt 0) {
            foreach ($rule in $result.RuleHits) {
                $allRuleHits += [PSCustomObject]@{
                    FileName = $result.FileName
                    MSGID = $result.MSGID
                    OverallScore = $result.Score
                    OverallResult = $result.Result
                    RuleScore = [math]::Round($rule.Score, 3)
                    RuleName = $rule.Rule
                    RuleDescription = $rule.Description
                    ProcessingTime = $result.ProcessingTime
                }
            }
        }
    }
    
    if ($allRuleHits.Count -gt 0) {
        $allRuleHits | Sort-Object FileName, RuleScore -Descending | Export-Csv -Path $allRulesPath -NoTypeInformation
        Write-Log "All rule hits exported to: $allRulesPath" "Info" "Green"
        Write-Log "Total rule hits exported: $($allRuleHits.Count)" "Info" "White"
    } else {
        Write-Log "No rule hits to export." "Warn" "Yellow"
    }
    
    # Export rule statistics summary
    if($RuleStats.AllRuleStats -and $RuleStats.AllRuleStats.Count -gt 0) {
        $ruleStatsPath = Join-Path $exportDir "RuleStats_$timestamp.csv"
        $RuleStats.AllRuleStats.GetEnumerator() | 
            ForEach-Object {
                [PSCustomObject]@{
                    Rule = $_.Key
                    HitCount = $_.Value.Count
                    Frequency = [math]::Round(($_.Value.Count / $RuleStats.MessagesWithRules) * 100, 2)
                    Score = [math]::Round($_.Value.Score, 3)
                    TotalScore = [math]::Round($_.Value.TotalScore, 3)
                    Description = $_.Value.Description
                }
            } |
            Sort-Object HitCount -Descending |
            Export-Csv -Path $ruleStatsPath -NoTypeInformation
        Write-Log "Rule statistics exported to: $ruleStatsPath" "Info" "Green"
    }
}

function Show-Summary {
    param($FinalResults)
    $resultsWithProcessingTime = $FinalResults | Where-Object { $_.PSObject.Properties['ProcessingTime'] }
    $successCount = ($FinalResults | Where-Object { $_.Success }).Count
    $failCount = $FinalResults.Count - $successCount
    $totalTime = if ($resultsWithProcessingTime.Count -gt 0) { ($resultsWithProcessingTime | Measure-Object ProcessingTime -Sum).Sum } else { 0 }
    $avgTime = if($resultsWithProcessingTime.Count -gt 0) { $totalTime / $resultsWithProcessingTime.Count } else { 0 }

    Write-Log "`n=== SUMMARY ===" "Info" "Cyan"
    Write-Log "Total files: $($FinalResults.Count)" "Info" "White"
    Write-Log "Successful: $successCount" "Info" "Green"
    Write-Log "Failed: $failCount" "Info" "Red"
    Write-Log "Total processing time: $totalTime ms" "Info" "White"
    Write-Log "Average time per file: $([math]::Round($avgTime, 2)) ms" "Info" "White"
    if ($totalTime -gt 0) {
        Write-Log "Throughput: $([math]::Round($resultsWithProcessingTime.Count / ($totalTime / 1000), 2)) files/second" "Info" "White"
    } else {
        Write-Log "Throughput: N/A (no processing time data or zero total time)" "Info" "White"
    }
}

# ---[ Main Execution ]---

$config = New-Configuration -MSGPath $MSGPath -MaxConcurrentJobs $MaxConcurrentJobs -RemoteHost $RemoteHost -Port $Port -EnableDebug $EnableDebug -LogResponses $LogResponses -LogPath $LogPath -ExportCSV $ExportCSV

# Remove the debug lines that were causing issues
Show-Banner $config
$Results = Invoke-SpamCheck -config $config -ScriptBlock $ScriptBlock

if(-not $Results -or $Results.Count -eq 0) {
    Write-Log "No results were returned from the spam check." "Warn" "Yellow"
    return
}

# Flatten the results array
$FinalResults = @()
foreach ($item in $Results) {
    if ($item -is [System.Collections.IEnumerable] -and $item -isnot [string]) {
        $FinalResults += $item
    } else {
        $FinalResults += $item
    }
}

$RuleStats = Get-RuleStatistics $FinalResults
Show-Results $FinalResults $config.EnableDebug $RuleStats
Show-Summary $FinalResults
Export-ResultsToCsv $config $FinalResults $RuleStats
