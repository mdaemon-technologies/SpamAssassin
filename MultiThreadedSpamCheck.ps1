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

# --- End optimized section ---

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
$MSGFiles = Get-ChildItem -Path $MSGPath -Filter *.msg -ErrorAction SilentlyContinue

if(-not $MSGFiles -or $MSGFiles.Count -eq 0) {
    Write-Warning "No .msg files found in $MSGPath"
    Write-Host "Please check the path and ensure .msg files exist."
    exit
}

Write-Host "Found $($MSGFiles.Count) MSG files to process" -ForegroundColor Green

# Create runspace pool
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrentJobs)
$RunspacePool.Open()

$Jobs = @()
$Results = @()

try {
    # Submit all jobs
    foreach($MSGFile in $MSGFiles) {
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
        }
        
        $Jobs += $Job
        Write-Host "Submitted job for: $($MSGFile.Name)"
    }
    
    Write-Host "`nWaiting for $($Jobs.Count) jobs to complete..." -ForegroundColor Yellow
    
    # Collect results with explicit job tracking
    $CompletedCount = 0
    $ProcessedJobFiles = @()  # Track which jobs we've actually processed
    #$maxWaitTime = 1800000  # 30 minutes maximum wait
    $waitStartTime = Get-Date
    $lastProgressTime = Get-Date
    $progressUpdateInterval = 10000  # 10 seconds

    while($Jobs.Count -gt 0) {
        $currentTime = Get-Date
        $elapsedTime = ($currentTime - $waitStartTime).TotalMilliseconds

        # Check for overall timeout
        #if($elapsedTime -gt $maxWaitTime) {
        #    Write-Warning "Maximum wait time exceeded ($([math]::Round($elapsedTime/1000, 1))s). Stopping job collection."
        #    Write-Host "Completed: $CompletedCount/$($MSGFiles.Count), Remaining jobs: $($Jobs.Count)" -ForegroundColor Yellow
        #    break
        #}

        # Show progress every 10 seconds
        $timeSinceLastProgress = ($currentTime - $lastProgressTime).TotalMilliseconds
        if($EnableDebug -and ($timeSinceLastProgress -gt $progressUpdateInterval)) {
            Write-Host "Progress update: $CompletedCount/$($MSGFiles.Count) completed, $($Jobs.Count) remaining jobs" -ForegroundColor Yellow
            $lastProgressTime = $currentTime
        }

        # Find completed jobs that haven't been processed yet
        $CompletedJobs = $Jobs | Where-Object { 
            $_.Handle.IsCompleted -and $_.File -notin $ProcessedJobFiles 
        }

        if($CompletedJobs.Count -eq 0) {
            # No new completed jobs, wait a bit and continue
            Start-Sleep -Milliseconds 1000
            continue
        }

        # Track jobs processed in this iteration
        $JobsProcessedThisIteration = @()

        foreach($CompletedJob in $CompletedJobs) {
            try {
                # Add timeout for EndInvoke
                $invokeStartTime = Get-Date
                $Result = $null

                try {
                    $Result = $CompletedJob.PowerShell.EndInvoke($CompletedJob.Handle)
                }
                catch [System.Management.Automation.RuntimeException] {
                    Write-Warning "RuntimeException for $($CompletedJob.File): $($_.Exception.Message)"
                    $Result = @{
                        FileName = $CompletedJob.File
                        Success = $false
                        Error = "PowerShell RuntimeException: $($_.Exception.Message)"
                        Result = ""
                        Score = ""
                        Threshold = ""
                        RuleCount = 0
                        ProcessingTime = 0
                        FullPath = ""
                        MSGID = ""
                        RuleHits = @()
                        DebugInfo = ""
                        ThreadLog = @("RuntimeException occurred")
                    }
                }
                catch {
                    Write-Warning "General exception for $($CompletedJob.File): $($_.Exception.Message)"
                    $Result = @{
                        FileName = $CompletedJob.File
                        Success = $false
                        Error = "PowerShell Exception: $($_.Exception.Message)"
                        Result = ""
                        Score = ""
                        Threshold = ""
                        RuleCount = 0
                        ProcessingTime = 0
                        FullPath = ""
                        MSGID = ""
                        RuleHits = @()
                        DebugInfo = ""
                        ThreadLog = @("Exception occurred during EndInvoke")
                    }
                }

                $invokeTime = ((Get-Date) - $invokeStartTime).TotalMilliseconds

                if($invokeTime -gt 5000) {
                    Write-Warning "EndInvoke took $([math]::Round($invokeTime, 0))ms for $($CompletedJob.File)"
                }

                # Handle null result
                if(-not $Result) {
                    Write-Warning "Null result returned for $($CompletedJob.File)"
                    $Result = @{
                        FileName = $CompletedJob.File
                        Success = $false
                        Error = "Null result returned"
                        Result = ""
                        Score = ""
                        Threshold = ""
                        RuleCount = 0
                        ProcessingTime = 0
                        FullPath = ""
                        MSGID = ""
                        RuleHits = @()
                        DebugInfo = ""
                        ThreadLog = @("Null result")
                    }
                }

                # Convert to display object
                $ResultObj = [PSCustomObject]@{
                    FileName = $Result.FileName
                    Success = $Result.Success
                    Result = $Result.Result
                    Score = $Result.Score
                    Threshold = $Result.Threshold
                    RuleCount = $Result.RuleCount
                    ProcessingTime = $Result.ProcessingTime
                    Error = $Result.Error
                    FullPath = $Result.FullPath
                    MSGID = $Result.MSGID
                    RuleHits = if($Result.RuleHits) { $Result.RuleHits -join "; " } else { "" }
                    DebugInfo = $Result.DebugInfo
                }

                $Results += $ResultObj
                $CompletedCount++

                # Track this job as processed in this iteration
                $JobsProcessedThisIteration += $CompletedJob.File

                Write-Host "Completed ($CompletedCount/$($MSGFiles.Count)): $($CompletedJob.File)"

 # Display thread log output
            if($Result.ThreadLog -and $Result.ThreadLog.Count -gt 0) {
                $Result.ThreadLog | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
            }

                if($Result.Success) {
                    $statusMsg = "Result: '$($Result.Result)', Score: '$($Result.Score)'"
                    if($Result.RuleCount -gt 0) {
                    $statusMsg += ", Rules: $($Result.RuleCount)"
                    Write-Host "  ✓ $statusMsg" -ForegroundColor Green
                    
                    # List individual rules with scores
                    Write-Host "    Rules triggered:" -ForegroundColor Cyan
                    $Result.RuleHits | ForEach-Object {
                        if($_ -match "^([^(]+)\(([\d.-]+)\)$") {
                            Write-Host "      $($Matches[1]): $($Matches[2])" -ForegroundColor Cyan
                        } else {
                            Write-Host "      ${_}: 0.0" -ForegroundColor Cyan
                        }
                    }
                } else {
                    Write-Host "  ✓ $statusMsg" -ForegroundColor Green
                }
                } else {
                    Write-Host "  ✗ Failed - Error: $($Result.Error)" -ForegroundColor Red
                }
            }
            catch {
                Write-Warning "Error collecting result for $($CompletedJob.File): $($_.Exception.Message)"

                # Track this job as processed even if it failed
                $JobsProcessedThisIteration += $CompletedJob.File

                # Create a failed result object for missing results
                $FailedResultObj = [PSCustomObject]@{
                    FileName = $CompletedJob.File
                    Success = $false
                    Result = "PowerShell Error"
                    Score = ""
                    Threshold = ""
                    RuleCount = 0
                    ProcessingTime = 0
                    Error = "PowerShell execution error: $($_.Exception.Message)"
                    FullPath = ""
                    MSGID = ""
                    RuleHits = ""
                    DebugInfo = ""
                }

                $Results += $FailedResultObj
                $CompletedCount++

                Write-Host "Completed ($CompletedCount/$($MSGFiles.Count)): $($CompletedJob.File) [ERROR]" -ForegroundColor Red
            }
            finally {
                try {
                    $CompletedJob.PowerShell.Dispose()
                } catch {
                    Write-Warning "Error disposing PowerShell for $($CompletedJob.File): $($_.Exception.Message)"
                }
            }
        }

        # Update the global processed files list with all jobs processed in this iteration
        $ProcessedJobFiles += $JobsProcessedThisIteration

        # Remove only the jobs we've actually processed in this iteration
        $oldJobCount = $Jobs.Count
        $Jobs = $Jobs | Where-Object { $_.File -notin $ProcessedJobFiles }
        $removedJobs = $oldJobCount - $Jobs.Count

        # This should now match exactly
        if($removedJobs -ne $JobsProcessedThisIteration.Count) {
            Write-Warning "Job count mismatch: removed $removedJobs jobs but processed $($JobsProcessedThisIteration.Count) jobs in this iteration"
            Write-Host "Jobs processed this iteration: $($JobsProcessedThisIteration -join ', ')" -ForegroundColor Yellow
            Write-Host "Total processed files: $($ProcessedJobFiles.Count)" -ForegroundColor Yellow
        } else {
            # Optional: Show successful processing count for debugging
            if($EnableDebug -and $JobsProcessedThisIteration.Count -gt 1) {
                Write-Host "Successfully processed $($JobsProcessedThisIteration.Count) jobs in this iteration" -ForegroundColor Green
            }
        }
    }

    # Force cleanup any remaining jobs
    if($Jobs.Count -gt 0) {
        Write-Warning "Forcing cleanup of $($Jobs.Count) remaining jobs"
        foreach($job in $Jobs) {
            try {
                # Try to get any result first if completed
                if($job.Handle.IsCompleted -and $job.File -notin $ProcessedJobFiles) {
                    try {
                        $result = $job.PowerShell.EndInvoke($job.Handle)
                        if($result) {
                            $ResultObj = [PSCustomObject]@{
                                FileName = $result.FileName
                                Success = $result.Success
                                Result = $result.Result
                                Score = $result.Score
                                Threshold = $result.Threshold
                                RuleCount = $result.RuleCount
                                ProcessingTime = $result.ProcessingTime
                                Error = $result.Error
                                FullPath = $result.FullPath
                                MSGID = $result.MSGID
                                RuleHits = if($result.RuleHits) { $result.RuleHits -join "; " } else { "" }
                                DebugInfo = $result.DebugInfo
                            }
                            $Results += $ResultObj
                            $CompletedCount++
                            Write-Host "Late completion: $($job.File)" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Warning "Error getting result from remaining job $($job.File): $($_.Exception.Message)"
                    }
                }

                $job.PowerShell.Stop()
                $job.PowerShell.Dispose()

                # Add a failed result for unprocessed jobs
                if($job.File -notin $ProcessedJobFiles) {
                    $FailedResultObj = [PSCustomObject]@{
                        FileName = $job.File
                        Success = $false
                        Result = "Timeout/Cleanup"
                        Score = ""
                        Threshold = ""
                        RuleCount = 0
                        ProcessingTime = 0
                        Error = "Job did not complete within timeout period"
                        FullPath = ""
                        MSGID = ""
                        RuleHits = ""
                        DebugInfo = ""
                    }
                    $Results += $FailedResultObj
                    Write-Host "Timeout cleanup: $($job.File)" -ForegroundColor Red
                }

            } catch {
                Write-Warning "Error force-disposing job $($job.File): $($_.Exception.Message)"
            }
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
    # Main results table
    $displayColumns = @("FileName", "Success", "Result", "Score", "RuleCount", "ProcessingTime")
    if($EnableDebug) {
        $displayColumns += "DebugInfo"
    }
    
    $Results | Format-Table $displayColumns -AutoSize
    
    # Rule analysis
    Write-Host "`n=== SPAM RULE ANALYSIS ===" -ForegroundColor Cyan
    
    $successfulResults = $Results | Where-Object { $_.Success -and $_.RuleHits }
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
$successCount = ($Results | Where-Object { $_.Success }).Count
$failCount = $Results.Count - $successCount
$totalTime = ($Results | Measure-Object ProcessingTime -Sum).Sum
$avgTime = if($Results.Count -gt 0) { $totalTime / $Results.Count } else { 0 }

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total files: $($Results.Count)"
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor Red
Write-Host "Total processing time: $totalTime ms"
Write-Host "Average time per file: $([math]::Round($avgTime, 2)) ms"
Write-Host "Throughput: $([math]::Round($Results.Count / ($totalTime / 1000), 2)) files/second"

# Export results conditionally
if($ExportCSV) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportDir = if($LogPath) { $LogPath } else { Get-Location }
    $csvPath = Join-Path $exportDir "SpamResults_$timestamp.csv"
    $Results | Export-Csv -Path $csvPath -NoTypeInformation
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