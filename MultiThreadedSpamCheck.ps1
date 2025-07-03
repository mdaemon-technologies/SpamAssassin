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

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
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
    return $result
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
    if ($outputBuffer -match "Message-Id:\s*(.*)" -or $outputBuffer -match "Message-ID:\s*(.*)") { $parseResult.MSGID = $Matches[1].Trim() }
    if ($headers -match "Spam:\s*(.*)") {
        $spamLine = $Matches[1].Trim()
        if ($spamLine -match "([^;]+);\s*([\d.-]+)\s*/\s*([\d.-]+)") {
            $parseResult.Result = $Matches[1].Trim()
            $parseResult.Score = $Matches[2].Trim()
            $parseResult.Threshold = $Matches[3].Trim()
        }
    }
    if ($body -and $body.Length -gt 0) {
        if ($body -match "(?s)Content analysis details:.*?pts rule name.*?description.*?-+\s*(.*?)(?:\n\s*\n|\r\n\s*\r\n|$)") {
            $analysisSection = $Matches[1]
            $rulePattern = "^\s*([\d.-]+)\s+([A-Z_][A-Z0-9_]*)\s+(.*?)$"
            $ruleLines = $analysisSection -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch "^\s*-+\s*$" }
            $detailedRules = @()
            foreach ($line in $ruleLines) {
                $cleanLine = $line.Trim()
                if ($cleanLine -match $rulePattern) {
                    $score = [decimal]$Matches[1]
                    $ruleName = $Matches[2].Trim()
                    $description = $Matches[3].Trim()
                    $detailedRules += [PSCustomObject]@{ Score = $score; Rule = $ruleName; Description = $description }
                }
            }
            if ($detailedRules.Count -gt 0) {
                $sortedRules = $detailedRules | Sort-Object Score -Descending
                $parseResult.RuleHits = $sortedRules | ForEach-Object { "$($_.Rule)($($_.Score))" }
                $parseResult.RuleCount = $detailedRules.Count
                $parseResult.TopRules = ($sortedRules | Select-Object -First 5 | ForEach-Object { "$($_.Rule)($($_.Score))" }) -join ", "
            }
        } else {
            $ruleMatches = [regex]::Matches($body, "^\s*([\d.-]+)\s+([A-Z_][A-Z0-9_]{2,})\s+.*$", [System.Text.RegularExpressions.RegexOptions]::Multiline)
            if ($ruleMatches.Count -gt 0) {
                $fallbackRules = @()
                foreach ($match in $ruleMatches) {
                    $score = [decimal]$match.Groups[1].Value
                    $ruleName = $match.Groups[2].Value.Trim()
                    $fallbackRules += [PSCustomObject]@{ Score = $score; Rule = $ruleName; Description = "Parsed from fallback method" }
                }
                if ($fallbackRules.Count -gt 0) {
                    $sortedRules = $fallbackRules | Sort-Object Score -Descending
                    $parseResult.RuleHits = $sortedRules | ForEach-Object { "$($_.Rule)($($_.Score))" }
                    $parseResult.RuleCount = $fallbackRules.Count
                    $parseResult.TopRules = ($sortedRules | Select-Object -First 5 | ForEach-Object { "$($_.Rule)($($_.Score))" }) -join ", "
                }
            }
        }
    }
    if ([string]::IsNullOrEmpty($parseResult.Score) -and $headers -match "X-Spam-Score:\s*([\d.-]+)") { $parseResult.Score = $Matches[1] }
    if ([string]::IsNullOrEmpty($parseResult.Threshold) -and $headers -match "X-Spam-(?:Level|Threshold):\s*([\d.-]+)") { $parseResult.Threshold = $Matches[1] }
    if ([string]::IsNullOrEmpty($parseResult.Result) -and $headers -match "SPAMD/[\d.]+\s+(\d+)\s+(.*)") {
        $code = $Matches[1]; $message = $Matches[2].Trim()
        if ($code -ne "0") { $parseResult.Result = "Error: Code $code - $message" }
    }
    return $parseResult
}

# MAIN EXECUTION
Write-Host "=== Multi-threaded SPAMC Email Processor with Rule Tracking ===" -ForegroundColor Cyan
Write-Host "Path: $MSGPath"
Write-Host "Host: ${RemoteHost}:${Port}"
Write-Host "Max Concurrent Jobs: $MaxConcurrentJobs"
if($EnableDebug) { Write-Host "Debug Mode: Enabled" -ForegroundColor Yellow }
if($LogResponses) { 
    $actualLogPath = if($LogPath) { Join-Path $LogPath "spamc_responses.log" } else { Join-Path (Get-Location) "spamc_responses.log" }
    Write-Host "Response Logging: Enabled -> $actualLogPath" -ForegroundColor Yellow 
}
if($ExportCSV) {
    $exportLocation = if($LogPath) { $LogPath } else { Get-Location }
    Write-Host "CSV Export: Enabled -> $exportLocation" -ForegroundColor Yellow
}
Write-Host ""

# Get function definitions
$GetResponseThreadedFunction = ${function:GetResponseThreaded}.ToString()
$ProcessBufferThreadedFunction = ${function:ProcessBufferThreaded}.ToString()

# Get MSG files
$AllMSGFiles = Get-ChildItem -Path $MSGPath -Filter *.msg -ErrorAction SilentlyContinue

if(-not $AllMSGFiles -or $AllMSGFiles.Count -eq 0) {
    Write-Warning "No .msg files found in $MSGPath"
    Write-Host "Please check the path and ensure .msg files exist."
    exit
}

$TotalFileCount = $AllMSGFiles.Count
Write-Host "Found $TotalFileCount MSG files to process" -ForegroundColor Green

# Create a thread-safe queue for the files
$FileQueue = [System.Collections.Concurrent.ConcurrentQueue[System.IO.FileInfo]]::new()
foreach ($file in $AllMSGFiles) {
    $FileQueue.Enqueue($file)
}

# Create runspace pool
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrentJobs)
$RunspacePool.Open()

$Jobs = @()
$Results = [System.Collections.ArrayList]::new()
$TotalProcessed = 0

try {
    # This loop manages the job queue, submitting new jobs as threads become available
    # and collecting results from completed jobs.
    while($TotalProcessed -lt $TotalFileCount) {
        
        # Submit new jobs until the runspace pool is busy or the queue is empty
        while ($Jobs.Count -lt $MaxConcurrentJobs -and !$FileQueue.IsEmpty) {
            $MSGFile = $null
            if ($FileQueue.TryDequeue([ref]$MSGFile)) {
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
                
                $Job = @{
                    PowerShell = $PowerShell
                    Handle = $PowerShell.BeginInvoke()
                    File = $MSGFile.Name
                    SubmitTime = Get-Date
                }
                
                $Jobs += $Job
                Write-Host "Submitted job for: $($MSGFile.Name)"
            }
        }
        
        # Wait for any job to complete
        if ($Jobs.Count -gt 0) {
            $waitHandles = $Jobs.Handle | ForEach-Object { $_.AsyncWaitHandle }
            [void][System.Threading.WaitHandle]::WaitAny($waitHandles, 60000) # 60-second timeout
        }

        # Collect results from all completed jobs
        $CompletedJobs = $Jobs | Where-Object { $_.Handle.IsCompleted }
        $RemainingJobs = @()

        foreach ($Job in $Jobs) {
            if ($Job.Handle.IsCompleted) {
                $ResultData = $null
                try {
                    $ResultData = $Job.PowerShell.EndInvoke($Job.Handle)
                    if ($ResultData) {
                        [void]$Results.Add([PSCustomObject]$ResultData)
                    } else {
                        # Create a failure result if EndInvoke returns null
                        $FailedResult = [PSCustomObject]@{
                            FileName = $Job.File; Success = $false; Error = "Job returned null result"; ProcessingTime = 0
                        }
                        [void]$Results.Add($FailedResult)
                        $ResultData = $FailedResult
                    }
                } catch {
                    # Create a failure result for exceptions during EndInvoke
                    $FailedResult = [PSCustomObject]@{
                        FileName = $Job.File; Success = $false; Error = "Job failed: $($_.Exception.Message)"; ProcessingTime = 0
                    }
                    [void]$Results.Add($FailedResult)
                    $ResultData = $FailedResult
                } finally {
                    $Job.PowerShell.Dispose()
                    $TotalProcessed++
                    
                    # Detailed real-time logging
                    Write-Host "Completed ($TotalProcessed/$TotalFileCount): $($Job.File)"
                    if ($ResultData) {
                        if ($EnableDebug -and $ResultData.ThreadLog) {
                            $ResultData.ThreadLog | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
                        }
                        if ($ResultData.Success) {
                            $statusMsg = "Result: '$($ResultData.Result)', Score: '$($ResultData.Score)'"
                            if ($ResultData.RuleCount -gt 0) {
                                $statusMsg += ", Rules: $($ResultData.RuleCount)"
                            }
                            Write-Host "  ✓ $statusMsg" -ForegroundColor Green
                            
                            if ($ResultData.RuleHits.Count -gt 0) {
                                Write-Host "    Rules triggered:" -ForegroundColor Cyan
                                $ResultData.RuleHits | ForEach-Object {
                                    if ($_ -match "^([^(]+)\(([\d.-]+)\)$") {
                                        Write-Host "      $($Matches[1]): $($Matches[2])" -ForegroundColor Cyan
                                    } else {
                                        Write-Host "      $_" -ForegroundColor Cyan
                                    }
                                }
                            }
                        } else {
                            Write-Host "  ✗ Failed - Error: $($ResultData.Error)" -ForegroundColor Red
                        }
                    }
                }
            } else {
                # If the job is not completed, keep it for the next iteration
                $RemainingJobs += $Job
            }
        }
        
        $Jobs = $RemainingJobs
        
        # If no jobs completed and the queue is empty, we are done
        if ($CompletedJobs.Count -eq 0 -and $FileQueue.IsEmpty) {
            break
        }
    }
}
finally {
    if($RunspacePool) {
        $RunspacePool.Close()
        $RunspacePool.Dispose()
    }
}

# Display results
Write-Host "`n=== PROCESSING RESULTS ===" -ForegroundColor Cyan

if($Results.Count -gt 0) {
    # Convert ArrayList to a standard array for processing
    $FinalResults = $Results.ToArray()

    # Main results table
    $displayColumns = @("FileName", "Success", "Result", "Score", "RuleCount", "ProcessingTime")
    if($EnableDebug) {
        $displayColumns += "DebugInfo"
    }
    
    $FinalResults | Format-Table $displayColumns -AutoSize
    
    # Rule analysis
    Write-Host "`n=== SPAM RULE ANALYSIS ===" -ForegroundColor Cyan
    
    $successfulResults = $FinalResults | Where-Object { $_.Success -and $_.RuleHits }
    $allRuleStats = @{}
    $totalMessages = $successfulResults.Count
    $messagesWithRules = 0
    
    foreach($result in $successfulResults) {
        if($result.RuleHits -and $result.RuleHits.Length -gt 0) {
            $messagesWithRules++
            $rules = $result.RuleHits -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            
            foreach($rule in $rules) {
                # Parse rule format: "RULE_NAME(score)" or just "RULE_NAME"
                if($rule -match "^([^(]+)\(([\d.-]+)\)$") {
                    $ruleName = $Matches[1].Trim()
                    $ruleScore = [decimal]$Matches[2]
                } else {
                    $ruleName = $rule.Trim()
                    $ruleScore = 0
                }
                
                if($ruleName -and $ruleName.Length -gt 2) {
                    if(-not $allRuleStats.ContainsKey($ruleName)) {
                        $allRuleStats[$ruleName] = @{
                            Count = 0
                            TotalScore = 0
                            Score = 0
                        }
                    }
                    
                    $allRuleStats[$ruleName].Count++
                    $allRuleStats[$ruleName].TotalScore += $ruleScore
                    if($ruleScore -gt $allRuleStats[$ruleName].Score) {
                        $allRuleStats[$ruleName].Score = $ruleScore
                    }
                }
            }
        }
    }
    
    if($allRuleStats.Count -gt 0) {
        Write-Host "Messages processed: $totalMessages"
        Write-Host "Messages with rules: $messagesWithRules"
        Write-Host "Unique rules found: $($allRuleStats.Count)"
        
        Write-Host "`nTop 25 Triggered Rules:"
        $allRuleStats.GetEnumerator() | 
            Sort-Object { $_.Value.Count } -Descending | 
            Select-Object -First 25 | 
            ForEach-Object {
                [PSCustomObject]@{
                    Rule = $_.Key
                    HitCount = $_.Value.Count
                    Frequency = "{0:P1}" -f ($_.Value.Count / $messagesWithRules)
                    Score = [math]::Round($_.Value.Score, 2)
                }
            } |
            Format-Table Rule, HitCount, Frequency, Score -AutoSize
            
        Write-Host "`nTop 25 Highest Scoring Rules:"
        $allRuleStats.GetEnumerator() | 
            Sort-Object { $_.Value.Score } -Descending | 
            Select-Object -First 25 | 
            ForEach-Object {
                [PSCustomObject]@{
                    Rule = $_.Key
                    Score = [math]::Round($_.Value.Score, 2)
                    HitCount = $_.Value.Count
                }
            } |
            Format-Table Rule, Score, HitCount -AutoSize
    } else {
        Write-Host "No SpamAssassin rules were found in the processed messages." -ForegroundColor Yellow
        if($EnableDebug) {
            Write-Host "Enable debug mode with -EnableDebug to see parsing details." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "No results to display." -ForegroundColor Red
}

# Summary statistics
$successCount = ($FinalResults | Where-Object { $_.Success }).Count
$failCount = $FinalResults.Count - $successCount
$totalTime = ($FinalResults | Measure-Object ProcessingTime -Sum).Sum
$avgTime = if($FinalResults.Count -gt 0) { $totalTime / $FinalResults.Count } else { 0 }

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total files: $($FinalResults.Count)"
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red
Write-Host "Total processing time: $totalTime ms"
Write-Host "Average time per file: $([math]::Round($avgTime, 2)) ms"
Write-Host "Throughput: $([math]::Round($FinalResults.Count / ($totalTime / 1000), 2)) files/second"

# Export results conditionally
if($ExportCSV) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportDir = if($LogPath) { $LogPath } else { Get-Location }
    $csvPath = Join-Path $exportDir "SpamResults_$timestamp.csv"
    $FinalResults | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nDetailed results exported to: $csvPath" -ForegroundColor Green
    
    # Export rule statistics if available
    if($allRuleStats -and $allRuleStats.Count -gt 0) {
        $ruleStatsPath = Join-Path $exportDir "RuleStats_$timestamp.csv"
        $allRuleStats.GetEnumerator() | 
            ForEach-Object {
                [PSCustomObject]@{
                    Rule = $_.Key
                    HitCount = $_.Value.Count
                    Frequency = [math]::Round(($_.Value.Count / $messagesWithRules) * 100, 2)
                    Score = [math]::Round($_.Value.Score, 3)
                    TotalScore = [math]::Round($_.Value.TotalScore, 3)
                }
            } |
            Sort-Object HitCount -Descending |
            Export-Csv -Path $ruleStatsPath -NoTypeInformation
        Write-Host "Rule statistics exported to: $ruleStatsPath" -ForegroundColor Green
    }
} else {
    Write-Host "`nCSV export disabled. Use -ExportCSV to create result files." -ForegroundColor Gray
}
