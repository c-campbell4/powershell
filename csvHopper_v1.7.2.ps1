##################q#######################################################################################
##
##   Author: cory.campbell.4@us.af.mil
## 
##   What this script is for...:
##        Import a CSV query from Splunk and search for lateral movement between a source ip (src_ip)
##        and a destination ip (dst_ip) i.e. the theory is that if A-> B, and B -> C, then B is 
##        potentially compromised. Lateral movement by way of RDP was the original target of this script 
## 
##   How this script works.....:
##        Step 02 imports a CSV, which is then filled into two separate arrays (src and dst) in step 03.
##        The main computation occurs in Steps 05 and 06, the outter and inner loops, respectively. The
##        script begins in src_ip index 0 and scans all indexes of dst_ip, searching for matching IPs.
##        If a match is found, the results are exported as CSV in Step 07. When a search is completed
##        for all indexes of dst_ip, the outter loop increments the src_ip to index 1 and continues to
##        loop until all duplicate IPs have been searched for. For more detailed information, please
##        reference the README.txt file.
##
##   Supporting Documents......:
##        Splunk_Query_RDP.txt
##        
##
#########################################################################################################



############################################
## 01.      File to import to CSV
############################################
$path = "P:\Cyber\splunk\VPN Mission\"            # directory path of script and data
$inFile = "$path\AFNET_VPN_31Oct_port1194.csv"               # csv File read in
$outFile = "$path\AFNET_VPN_31Oct_port1194_results.csv"      # designate filepath for target data to be written to


## Test for active file
Clear-Host
$bool = Test-Path -Path $inFile
Write-Host "Verifying inFile is found    : $bool"

## If no inFile is found, terminate script
if ( $bool -match "False") {
    Write-Host "Terminating Script due to no `$inFile found"
    exit
}


$origFile = Import-Csv $inFile
$origIndex = $origFile.count
## Remove duplicate src,dst IPs from original csv file
$workingFile = Import-Csv $inFile | sort src_ip, dst_ip -Unique 
## Calculate number of duplicates
$duplicates = $origIndex - $maxIndex

####################################
## 02. Import CSV to source_ip array
##       Define Variables
####################################
$maxIndex = $workingFile.count      # set max index/array size
$srcArray = @(0..$maxIndex)         # init source_ip Array
$dstArray = @(0..$maxIndex)         # init destination_ip Array
$dupArray = @(0..$maxIndex)         # init duplicates Array
$dupsPositive = 0                   # test var counter for duplicates found
$dupsNegative = 0                   # test var counter for duplicates NOT found 




####################################
## 03. Fill src and dst Arrays
####################################
For ($i = 0; $i -lt $maxIndex; $i++ ) {
    $srcArray[$i] = $workingFile[$i].src_ip
    $dstArray[$i] = $workingFile[$i].dst_ip
}

<#
Write-Host "Original csv Index size.........: $origIndex"
Write-Host "Removing $duplicates duplicates"
Write-Host "New Index size to be scannded...: $maxIndex" 
Start-Sleep -s 2
Write-Host "Preparing Search...."
Start-Sleep -s 2
Write-Host "Press any key to continue ....."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")   
#>

####################################
## 04. Prepare terminal for script execution
##       Init stop watch to time loop efficiency
####################################
Clear-Host
Write-Host "Number of IPs to be searched: : $maxIndex"
Write-Host "Beginning Search.... "

## Time the Efficiency of Outter Loop
$stopWatch = new-object system.diagnostics.stopwatch
$stopWatch.Start()



####################################
## 05. Outter Loop indexes $srcArray
####################################
For ($i = 0; $i -lt $maxIndex; $i++) {


    ####################################
    ## 06. Calculate & Print Status of Pairing Loop
    ####################################
    $src_status = ( $i / $maxIndex ) * 100        # Caclulate percentage to completion for src_ip
    $src_status = [math]::Round($src_status,4)    # Round percentage to four decimal places
    Write-Progress -id 1 -Activity "Searching Source IP Index...: $i" -Status "Status: $src_status%" 

    

    ####################################
    ## 07. Inner Loop
    ####################################
    For ($c = 0; $c -lt $srcArray.length; $c++) {



        if ( $dstArray[$c] -eq $srcArray[$i] ) { 
        <#
        ####################################
        ## xx. Calculate & Print Status of Pairing Loop
        ####################################
        $dst_status = ( $c / $maxIndex ) * 100        # Caclulate percentage to completion for src_ip
        $dst_status = [math]::Round($dst_status,4)    # Round percentage to four decimal places
        Write-Progress -id 2 -Activity "Searching Dest IP Index...: $c" -Status "Status: $dst_status%"
        #> 

            ## Prepare data for export to csv
            $dupFound = [pscustomobject]@{ 
                                        <#  'A_src_ip_c' = $workingFile[$c].src_ip;
                                            'B_src_ip_i' = $workingFile[$i].src_ip; 
                                            'C_dst_ip_i' = $workingFile[$i].dst_ip; #>
                                            'src_ip_A' = $srcArray[$c];
                                            'dst_ip_B' = $srcArray[$i];
                                            'dst_ip_C' = $dstArray[$i];
                                            }

            ## Export data to csv 
            $dupFound | Export-Csv -NoTypeInformation -Append -Path $outFile

            ## Counter for duplicates found
            $dupsPositive++; 
        }
        else {
            $dupsNegative++
        }
    }
} 


####################################
## 97. End StopWatch for Pairing Loop
####################################
$stopWatch.Stop()
$totalSeconds = $stopWatch.Elapsed.TotalSeconds      # Fetch total seconds ran
$totalMinutes = $stopWatch.Elapsed.TotalMinutes      # Fetch total minutes ran
$totalHours = $stopWatch.Elapsed.TotalHours          # Fetch total hours ran
$totalSeconds = [math]::Round($totalSeconds,2)       # Round Seconds to nearest two decimal places
$totalMinutes = [math]::Floor($totalMinutes)         # Round Minutes down
$totalHours = [math]::Floor($totalHours)             # Round Hours down

####################################
## 98. Print Script Efficiency
####################################
Write-Host " "
Write-Host "********************"
Write-Host "Total Hours......:  $totalHours"
Write-Host "Total Minutes....:  $totalMinutes"
Write-Host "Total Seconds....:  $totalSeconds"



####################################
## 99. Print and display End Results
#################################### 
# If results found...
if ( $dupsPositive -gt 0 ) {
    Write-Host " "
    Write-Host "**************************"
    Write-Host "Duplicate IPs stored in `$outFile <$outFile>:   " -ForegroundColor Yellow
    Import-Csv $outFile 

  # Else, no results found
} else {
    Write-Host " "
    Write-Host "**************************"
    Write-Host "No Duplicate IPs found." -ForegroundColor Yellow
    Write-Host "No Indicator of lateral movements evident" 
}







#########################################################################################################
##
## Version 1.2...: 
##     - Improved Status Bar for running Script 
##     - Removed Write-Host for each line of Scan Index src_ip
##     - Improved Write-Host Output before outter loop begins
##
## Version 1.3...:
##     - Added a Stop Watch ($stopWatch) to time the efficiency of the Algorithm
##     - Added documentation of Code Segment 04 for intial refinement of documentation
##
## Version 1.4...:
##     - Removed variables from global: entries. Global vars created issues because when the 
##         script was reran, it would not overwrite previous variables and would use the old ones.
##         This especially created issues because it would not read updated file path variables.
##     - Added more detailed documentation to top of script
##     - Added Further Development Notes documentation to bottom of script
##
## Version 1.5...:
##     - Implemented line to remove duplicates from inFile before parsing the data to their 
##         respective src and dst IPs. Removal of duplicates on big data test file cut down
##         number of events to scan from 114k to 9.6k, cutting run time down from 12 hrs to 36 minutes!
##           i.   I think I can further improve efficiency as there seems to be a slowdown when 
##                duplicates are found and appended to the $outFile.csv
##     - Changed some variables...: 
##           i.   renamed original $inFile to $workingFile. Includes line for removing duplicates 
##           ii.  renamed $filepath to $inFile
##
## Version 1.6...:
##     - Implemented a test at the beginning of the script to test that an $inFile was found. If
##         not found, terminate script
##     - Modified Inner Loop to add a field on pscustom object to be able to export-csv to show
##         lateral movement. The script can now show A → B → C connections. In the script, the A
##         would be the src_ip; the B would be the dest IP that is also a connection for hop as 
##         a src_ip i.e. (dst_ip → src_ip); the C is then the dst_ip from the hop. Verified 
##         accuracy of data on results pulled by Splunk by verifying the A → B → C hops manually.
##
## Further Development Notes:
##     - Should include a counter for indexes searched, just in case a large search gets interrupted
##         accidentally, and it can be resumed from where it left off bc the output file would still
##         be written to. OR can create a safeguard somehow so you don't accidentally CTL+C the script
##     √ v1.5: Remove Duplicate Findings that are being exported to $outFile
##     √ Need to find a way to effectively display A -> B -> C
##     - Is there a way to trace the trail to the end of the Rainbow? i.e. A → B → C → D ► End
##     - Implement a function for the main pairing loop so that it can easily be ran again to find 
##         the next hop. Implement more functions to clean up code
##     - Implement an option, separate from RDP, which pulls the src and dst IPs from a Splunk Query and 
##         this new option to check the subnets of all src IPs going to a dst or vice versa and map out
##         the bases in direct communication. If they are from separate units or bases it may be 
##         suspicious. Can also try to look for something from one unit to another for something weird
##
##
## Useful Links:
##   https://stackify.com/powershell-commands-every-developer-should-know/
##   https://stackoverflow.com/questions/3917592/why-do-i-need-to-have-my-functions-written-first-in-my-powershell-script
##   https://www.red-gate.com/simple-talk/sysadmin/powershell/powershell-one-liners-variables-parameters-properties-and-objects/
##   https://devblogs.microsoft.com/scripting/use-powershell-to-remove-duplicate-lines-from-a-csv-file/
##   https://blogs.technet.microsoft.com/ashleymcglone/2017/08/07/use-hash-tables-to-go-faster-than-powershell-compare-object/
##   https://stackoverflow.com/questions/3740128/pscustomobject-to-hashtable
##   https://blogs.technet.microsoft.com/ashleymcglone/2017/07/12/slow-code-top-5-ways-to-make-your-powershell-scripts-run-faster/
##   http://powershelltutorial.net/Home/PowerShell-Array-Hashes-Variable
##   https://www.reddit.com/r/PowerShell/comments/9nbbxz/readhost_into_an_array/
##
#########################################################################################################