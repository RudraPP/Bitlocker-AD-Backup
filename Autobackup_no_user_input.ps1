<#

Author : Rudra Prasad Paul

#>



Function IsElevated
{

    Write-Debug "IsElevated"

    [System.Security.Principal.WindowsIdentity]$windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [System.Security.Principal.WindowsPrincipal]$windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsIdentity)
    [System.Security.Principal.WindowsBuiltInRole]$adminRole="Administrator"
    [bool]$elevated=$windowsPrincipal.IsInRole($adminRole)

    Write-Debug "IsElevated: Return $elevated"

    return $elevated
}


Set-ExecutionPolicy Unrestricted 
 Write-Output "Checking prerequisites ..."

    if (-not (IsElevated))
    {
         Write-Host "Script must run with elevated privileges." -ForegroundColor Red
         exit;
    }
    else
    { 
         Write-Output "OK"
    }


	
	

try{

$BitLocker = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" -Filter "DriveLetter = 'C:'" -ErrorAction Stop
$encrypt="0"


                $ProtectorIds = $BitLocker.GetKeyProtectors("0").volumekeyprotectorID       

                foreach ($ProtectorID in $ProtectorIds){

                $KeyProtectorType = $BitLocker.GetKeyProtectorType($ProtectorID).KeyProtectorType

                        if($KeyProtectorType -eq 3){

                        Write-Host "Numerical Password is present and ID is :"  $ProtectorID -ForegroundColor Yellow

                            $encrypt="1"
                            $AzureAD = dsregcmd /status | ?{$_ -match "AzureAdJoined"}  
                            $Domainjoined = dsregcmd /status | ?{$_ -match "DomainJoined"}  



                        
                            $adback = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSActiveDirectoryBackup").OSActiveDirectoryBackup
                            #Write-Host $adback

                                if($Domainjoined -notmatch "YES" ){
                                        Write-Host "Machine is not domain joined....."  -ForegroundColor Red
                                        exit
                                }


                                if( $Domainjoined -match "YES")
                                    {
                                        if($adback -eq "1")
                                            {
    
                                            manage-bde -protectors -adbackup c: -id $ProtectorID

                                            Write-Host "`n"

                                            }
                                        else
                                            {
                                            Write-Host "Please Check the policy....." -ForegroundColor Red
                                            exit
                                    
                                            }
                                    }

                        
                            
                                if($AzureAD -match "YES")
                                {
                                 

                                    if($Domainjoined -match "YES")
                                        {
    
                                        manage-bde -protectors -aadbackup c: -id $ProtectorID
                                        }
                                    else
                                        {
                                        Write-Host "Machine is not domain joined....." -ForegroundColor Red
                                        exit
                                    
                                        }
                               
                                }                        

                            
                            
                        ;break
                     
                        }
                   }

                   if($encrypt -eq "0"){
                   
                   Write-Host "Numerical Password is NOT present. Please encrypt the machine........" -ForegroundColor Red
                   
                   }

}
catch
{
Write-Host "This is not supported on this Operating system" -ForegroundColor Yellow
}