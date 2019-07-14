Clear-Host


function Get-DecryptedStringOptions {

    [CmdletBinding()]
    param(
         [Parameter(Mandatory=$true)]
         [String] $source
        ,[Int]    $max_first_interval  = 5
        ,[Int]    $max_second_interval = 5
    )

    BEGIN {}
    PROCESS {

        # All variations up to max
        $(foreach ($x in 1..$max_first_interval){ foreach ($y in 1..$max_second_interval){ ,($x,$y,$($x + $y)) }}) | % {
            $interval1  = $_[0]
            $interval2  = $_[1]
            $combined   = $_[2]
            
            # PIPELINE TO GENERATE THE DECODED STRING
            $source.Replace([Environment]::NewLine,'').Replace(' ','').ToCharArray() | % {   
                $i = 1     # track the position in the encrypted string
                $out = ''  # decoded string for output
            }{  
                # character is output if it matches an interval (identified by using mod)
                if ( $i++ % $combined -in ($interval1,0) ){ $out += $_ }
            }{  
                New-Object -Type PSCustomObject -property @{
                     "interval1"  = $interval1
                    ;"interval2"  = $interval2
                    ;"output"     = $out  
                }
            }
        }

    }

    END {}

}



$crypto = @"
P k T r 2 s z 2 * c F -
r a z 7 G u D 4 w 6 U #
g c t K 3 E @ B t 1 a Y
Q P i c % 7 0 5 Z v A e
W 6 j e P R f p m I ) H
y ^ L o o w C n b J d O
S i 9 M b e r # ) i e U
* f 2 Z 6 M S h 7 V u D
5 a ( h s v 8 e l 1 o W
Z O 7 l p K y J l D z $
- j I @ t T 2 3 R a i k
q = F & w B 6 c % H l y
"@

Get-DecryptedStringOptions -source $crypto -max_first_interval 15 -max_second_interval 15 | ft -property interval1, interval2, output

