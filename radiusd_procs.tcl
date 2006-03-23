# Author: Vlad Seryakov vlad@crystalballinc.com
# March 2006

namespace eval radius {

}

ns_schedule_proc -once 0 radius::init

# Global RADIUS initialization
proc radius::init {} {

    radius::dictinit
    # Load local system users
    radius::loadusers
    # Load users file
    set config [file dirname [ns_info config]]/radius.tcl
    if { [file exists $config] } { source $config }
    ns_log Notice radius::init: loaded
}

# RADIUS server handler
proc radius::server { args } {

    switch -- [ns_radius reqget code] {
     1 {
       # Authentication request
       set ok 0
       set name [ns_radius reqget User-Name]
       set passwd [ns_radius reqget User-Password]
       set user [ns_radius userfind $name]
       foreach { key val } [lindex $user 0] {
         switch -- $key {
          user-password {
            # Clear text password
            if { $passwd == $val } {
              set ok 1
            }
          }
          
          crypt-password {
            # Encrypted password
            if { [ns_crypt $passwd $val] == $val } {
              set ok 1
            }
          }
          
          auth-profile {
            # Take attributes from specified profile user
            set profile [ns_radius userfind $val]
            if { $profile != "" } {
              eval ns_radius reqset [lindex $profile 1]
            }
          }
         }
       }
       if { $ok } {
         ns_radius reqset code 2
         foreach { key val } [lindex $user 1] {
           ns_radius reqset $key $val
         }
       } else {
         ns_radius reqset code 3
       }
       ns_log Notice radiusd: $name: auth = $ok
     }
     
     4 {
       # Accounting request
       ns_radius reqset code 5
       ns_log Notice radiusd: acct request: [ns_radius reqlist]
     }
     
     default {
       ns_log Error radiusd: unknown request: [ns_radius reqlist]
     }
    }
}

# Load local users from /etc/sahdow if accessable
proc radius::loadusers {} {

    if { [catch { set fd [open /etc/shadow] }] } { return }
    while { ![eof $fd] } {
      set line [split [gets $fd] :]
      # Keep only non empty passwords
      if { [string index [lindex $line 1] 0] == {$} } {
        ns_radius useradd [lindex $line 0] "Crypt-Password [lindex $line 1] Auth-Profile System-Profile"
      }
    }
    close $fd
}

# Initialization of RADIUS dictionaries
proc radius::dictinit {} {

    # Add localhost client
    ns_radius clientadd localhost localsecret

    # Standard attributes
    ns_radius dictadd User-Name 1 0 string
    ns_radius dictadd User-Password 2 0 string
    ns_radius dictadd CHAP-Password 3 0 string
    ns_radius dictadd NAS-IP-Address 4 0 ipaddr
    ns_radius dictadd NAS-Port-Id 5 0 integer
    ns_radius dictadd Service-Type 6 0 integer Login-User 1 Framed-User 2 Dialback-Login-User 3 Dialback-Framed-User 4 Outbound-User 5 Shell-User 6 NAS-Prompt-User 7 Authenticate-Only 8 Callback-NAS-Prompt 9 Call-Check 10 Callback-Administrative 11
    ns_radius dictadd Framed-Protocol 7 0 integer PPP 1 SLIP 2 ARAP 3 GANDALF-SLMLP 4 XYLOGICS-IPX-SLIP 5 X75 6
    ns_radius dictadd Framed-IP-Address 8 0 ipaddr
    ns_radius dictadd Framed-IP-Netmask 9 0 ipaddr
    ns_radius dictadd Framed-Routing 10 0 integer None 0 Broadcast 1 Listen 2 Broadcast-Listen 3
    ns_radius dictadd Filter-Id 11 0 string
    ns_radius dictadd Framed-MTU 12 0 integer
    ns_radius dictadd Framed-Compression 13 0 integer Van-Jacobsen-TCP-IP 1 IPX-Header 2 Stac-LZS 3
    ns_radius dictadd Login-IP-Host 14 0 ipaddr
    ns_radius dictadd Login-Service 15 0 integer Telnet 0 Rlogin 1 TCP-Clear 2 PortMaster 3 LAT 4 X.25-PAD 5 X.25-T3POS 6 TCP-Clear-Quiet 8
    ns_radius dictadd Login-TCP-Port 16 0 integer
    ns_radius dictadd Reply-Message 18 0 string
    ns_radius dictadd Callback-Number 19 0 string
    ns_radius dictadd Callback-Id 20 0 string
    ns_radius dictadd Framed-Route 22 0 string
    ns_radius dictadd Framed-IPX-Network 23 0 ipaddr
    ns_radius dictadd State 24 0 string
    ns_radius dictadd Class 25 0 string
    ns_radius dictadd Vendor-Specific 26 0 string
    ns_radius dictadd Session-Timeout 27 0 integer
    ns_radius dictadd Idle-Timeout 28 0 integer
    ns_radius dictadd Termination-Action 29 0 integer
    ns_radius dictadd Called-Station-Id 30 0 string
    ns_radius dictadd Calling-Station-Id 31 0 string
    ns_radius dictadd NAS-Identifier 32 0 string
    ns_radius dictadd Proxy-State 33 0 string
    ns_radius dictadd Login-LAT-Service 34 0 string
    ns_radius dictadd Login-LAT-Node 35 0 string
    ns_radius dictadd Login-LAT-Group 36 0 string
    ns_radius dictadd Framed-AppleTalk-Link 37 0 integer
    ns_radius dictadd Framed-AppleTalk-Network 38 0 integer
    ns_radius dictadd Framed-AppleTalk-Zone 39 0 string
    ns_radius dictadd Acct-Status-Type 40 0 integer Start 1 Stop 2 Interim-Update 3 Accounting-On 7 Accounting-Off 8 Tunnel-Start 9 Tunnel-Stop 10 Tunnel-Reject 11 Tunnel-Link-Start 12 Tunnel-Link-Stop 13 Tunnel-Link-Reject 14 Failed 15
    ns_radius dictadd Acct-Delay-Time 41 0 integer
    ns_radius dictadd Acct-Input-Octets 42 0 integer
    ns_radius dictadd Acct-Output-Octets 43 0 integer
    ns_radius dictadd Acct-Session-Id 44 0 string
    ns_radius dictadd Acct-Authentic 45 0 integer RADIUS 1 Local 2 Remote 3
    ns_radius dictadd Acct-Session-Time 46 0 integer
    ns_radius dictadd Acct-Input-Packets 47 0 integer
    ns_radius dictadd Acct-Output-Packets 48 0 integer
    ns_radius dictadd Acct-Terminate-Cause 49 0 integer User-Request 1 Lost-Carrier 2 Lost-Service 3 Idle-Timeout 4 Session-Timeout 5 Admin-Reset 6 Admin-Reboot 7 Port-Error 8 NAS-Error 9 NAS-Request 10 NAS-Reboot 11 Port-Unneeded 12 Port-Preempted 13 Port-Suspended 14 Service-Unavailable 15 Callback 16 User-Error 17 Host-Request 18
    ns_radius dictadd Acct-Multi-Session-Id 50 0 string
    ns_radius dictadd Acct-Link-Count 51 0 integer
    ns_radius dictadd CHAP-Challenge 60 0 string
    ns_radius dictadd NAS-Port-Type 61 0 integer Async 0 Sync 1 ISDN 2 ISDN-V120 3 ISDN-V110 4 Virtual 5 PIAFS 6 HDLC-Clear-Channel 7 X.25 8 X.75 9 G.3-Fax 10 SDSL 11 ADSL-CAP 12 ADSL-DMT 13 IDSL 14 Ethernet 15
    ns_radius dictadd Port-Limit 62 0 integer
    ns_radius dictadd Login-LAT-Port 63 0 integer
    ns_radius dictadd Connect-Info 77 0 string
    ns_radius dictadd Old-Huntgroup-Name 221 0 string
    ns_radius dictadd Fall-Through 500 0 integer
    ns_radius dictadd Add-Port-To-IP-Address 501 0 integer
    ns_radius dictadd Exec-Program 502 0 string
    ns_radius dictadd Exec-Program-Wait 503 0 string
    ns_radius dictadd User-Category 1029 0 string
    ns_radius dictadd Group-Name 1030 0 string
    ns_radius dictadd Huntgroup-Name 1031 0 string
    ns_radius dictadd Simultaneous-Use 1034 0 integer
    ns_radius dictadd Strip-User-Name 1035 0 integer
    ns_radius dictadd Old-Fall-Through 1036 0 integer
    ns_radius dictadd Old-Add-Port-To-IP-Address 1037 0 integer
    ns_radius dictadd Old-Exec-Program 1038 0 string
    ns_radius dictadd Old-Exec-Program-Wait 1039 0 string
    ns_radius dictadd Hint 1040 0 string
    ns_radius dictadd Pam-Auth 1041 0 string
    ns_radius dictadd Login-Time 1042 0 string
    ns_radius dictadd Realm 1045 0 string
    ns_radius dictadd Expiration 21 0 date
    # Non protocol attrobutes
    ns_radius dictadd Auth-Type 1000 0 integer Local 0 System 1 SecurID 2 Crypt-Local 3 Reject 4 ActivCard 5
    ns_radius dictadd Auth-Profile 1001 0 string
    ns_radius dictadd Menu 1002 0 string
    ns_radius dictadd Termination-Menu 1003 0 string
    ns_radius dictadd Prefix 1004 0 string
    ns_radius dictadd Suffix 1005 0 string
    ns_radius dictadd Group 1006 0 string
    ns_radius dictadd Crypt-Password 1007 0 string
    ns_radius dictadd Connect-Rate 1008 0 integer

    # Tunnel attributes
    ns_radius dictadd Tunnel-Type 64 0 integer PPTP 1 L2F 2 L2TP 3 ATMP 4 VTP 5 AH 6 IP-IP 7 MIN-IP-IP 8 ESP 9 GRE 10 DVS 11 IP-in-IP 12
    ns_radius dictadd Tunnel-Medium-Type 65 0 integer
    ns_radius dictadd Acct-Tunnel-Client-Endpoint 66 0 string
    ns_radius dictadd Tunnel-Server-Endpoint 67 0 string
    ns_radius dictadd Acct-Tunnel-Connection-Id 68 0 string
    ns_radius dictadd Tunnel-Password 69 0 string
    ns_radius dictadd Private-Group-Id 75 0 integer
    ns_radius dictadd Tunnel-Assignment-ID 82 0 string

    # Ascend attributes
    ns_radius dictadd Ascend-FCP-Parameter 119 0 string
    ns_radius dictadd Ascend-Modem-PortNo 120 0 integer
    ns_radius dictadd Ascend-Modem-SlotNo 121 0 integer
    ns_radius dictadd Ascend-Modem-ShelfNo 122 0 integer
    ns_radius dictadd Ascend-Call-Attempt-Limit 123 0 integer
    ns_radius dictadd Ascend-Call-Block-Duration 124 0 integer
    ns_radius dictadd Ascend-Maximum-Call-Duration 125 0 integer
    ns_radius dictadd Ascend-Temporary-Rtes 126 0 integer
    ns_radius dictadd Ascend-Tunneling-Protocol 127 0 integer
    ns_radius dictadd Ascend-Shared-Profile-Enable 128 0 integer
    ns_radius dictadd Ascend-Primary-Home-Agent 129 0 string
    ns_radius dictadd Ascend-Secondary-Home-Agent 130 0 string
    ns_radius dictadd Ascend-Dialout-Allowed 131 0 integer
    ns_radius dictadd Ascend-Client-Gateway 132 0 ipaddr
    ns_radius dictadd Ascend-BACP-Enable 133 0 integer
    ns_radius dictadd Ascend-DHCP-Maximum-Leases 134 0 integer
    ns_radius dictadd Ascend-Client-Primary-DNS 135 0 ipaddr
    ns_radius dictadd Ascend-Client-Secondary-DNS 136 0 ipaddr
    ns_radius dictadd Ascend-Client-Assign-DNS 137 0 integer
    ns_radius dictadd Ascend-User-Acct-Type 138 0 integer
    ns_radius dictadd Ascend-User-Acct-Host 139 0 ipaddr
    ns_radius dictadd Ascend-User-Acct-Port 140 0 integer
    ns_radius dictadd Ascend-User-Acct-Key 141 0 string
    ns_radius dictadd Ascend-User-Acct-Base 142 0 integer
    ns_radius dictadd Ascend-User-Acct-Time 143 0 integer
    ns_radius dictadd Ascend-Assign-IP-Client 144 0 ipaddr
    ns_radius dictadd Ascend-Assign-IP-Server 145 0 ipaddr
    ns_radius dictadd Ascend-Assign-IP-Global-Pool 146 0 string
    ns_radius dictadd Ascend-DHCP-Reply 147 0 integer
    ns_radius dictadd Ascend-DHCP-Pool-Number 148 0 integer
    ns_radius dictadd Ascend-Expect-Callback 149 0 integer
    ns_radius dictadd Ascend-Event-Type 150 0 integer
    ns_radius dictadd Ascend-Session-Svr-Key 151 0 string
    ns_radius dictadd Ascend-Multicast-Rate-Limit 152 0 integer
    ns_radius dictadd Ascend-IF-Netmask 153 0 ipaddr
    ns_radius dictadd Ascend-Remote-Addr 154 0 ipaddr
    ns_radius dictadd Ascend-Multicast-Client 155 0 integer
    ns_radius dictadd Ascend-FR-Circuit-Name 156 0 string
    ns_radius dictadd Ascend-FR-LinkUp 157 0 integer
    ns_radius dictadd Ascend-FR-Nailed-Grp 158 0 integer
    ns_radius dictadd Ascend-FR-Type 159 0 integer
    ns_radius dictadd Ascend-FR-Link-Mgt 160 0 integer
    ns_radius dictadd Ascend-FR-N391 161 0 integer
    ns_radius dictadd Ascend-FR-DCE-N392 162 0 integer
    ns_radius dictadd Ascend-FR-DTE-N392 163 0 integer
    ns_radius dictadd Ascend-FR-DCE-N393 164 0 integer
    ns_radius dictadd Ascend-FR-DTE-N393 165 0 integer
    ns_radius dictadd Ascend-FR-T391 166 0 integer
    ns_radius dictadd Ascend-FR-T392 167 0 integer
    ns_radius dictadd Ascend-Bridge-Address 168 0 string
    ns_radius dictadd Ascend-TS-Idle-Limit 169 0 integer
    ns_radius dictadd Ascend-TS-Idle-Mode 170 0 integer
    ns_radius dictadd Ascend-DBA-Monitor 171 0 integer
    ns_radius dictadd Ascend-Base-Channel-Count 172 0 integer
    ns_radius dictadd Ascend-Minimum-Channels 173 0 integer
    ns_radius dictadd Ascend-IPX-Route 174 0 string
    ns_radius dictadd Ascend-FT1-Caller 175 0 integer
    ns_radius dictadd Ascend-Backup 176 0 string
    ns_radius dictadd Ascend-Call-Type 177 0 integer
    ns_radius dictadd Ascend-Group 178 0 string
    ns_radius dictadd Ascend-FR-DLCI 179 0 integer
    ns_radius dictadd Ascend-FR-Profile-Name 180 0 string
    ns_radius dictadd Ascend-Ara-PW 181 0 string
    ns_radius dictadd Ascend-IPX-Node-Addr 182 0 string
    ns_radius dictadd Ascend-Home-Agent-IP-Addr 183 0 ipaddr
    ns_radius dictadd Ascend-Home-Agent-Password 184 0 string
    ns_radius dictadd Ascend-Home-Network-Name 185 0 string
    ns_radius dictadd Ascend-Home-Agent-UDP-Port 186 0 integer
    ns_radius dictadd Ascend-Multilink-ID 187 0 integer
    ns_radius dictadd Ascend-Num-In-Multilink 188 0 integer
    ns_radius dictadd Ascend-First-Dest 189 0 ipaddr
    ns_radius dictadd Ascend-Pre-Input-Octets 190 0 integer
    ns_radius dictadd Ascend-Pre-Output-Octets 191 0 integer
    ns_radius dictadd Ascend-Pre-Input-Packets 192 0 integer
    ns_radius dictadd Ascend-Pre-Output-Packets 193 0 integer
    ns_radius dictadd Ascend-Maximum-Time 194 0 integer
    ns_radius dictadd Ascend-Disconnect-Cause 195 0 integer
    ns_radius dictadd Ascend-Connect-Progress 196 0 integer
    ns_radius dictadd Ascend-Data-Rate 197 0 integer
    ns_radius dictadd Ascend-PreSession-Time 198 0 integer
    ns_radius dictadd Ascend-Token-Idle 199 0 integer
    ns_radius dictadd Ascend-Token-Immediate 200 0 integer
    ns_radius dictadd Ascend-Require-Auth 201 0 integer
    ns_radius dictadd Ascend-Number-Sessions 202 0 string
    ns_radius dictadd Ascend-Authen-Alias 203 0 string
    ns_radius dictadd Ascend-Token-Expiry 204 0 integer
    ns_radius dictadd Ascend-Menu-Selector 205 0 string
    ns_radius dictadd Ascend-Menu-Item 206 0 string
    ns_radius dictadd Ascend-PW-Warntime 207 0 integer
    ns_radius dictadd Ascend-PW-Lifetime 208 0 integer
    ns_radius dictadd Ascend-IP-Direct 209 0 ipaddr
    ns_radius dictadd Ascend-PPP-VJ-Slot-Comp 210 0 integer
    ns_radius dictadd Ascend-PPP-VJ-1172 211 0 integer
    ns_radius dictadd Ascend-PPP-Async-Map 212 0 integer
    ns_radius dictadd Ascend-Third-Prompt 213 0 string
    ns_radius dictadd Ascend-Send-Secret 214 0 string
    ns_radius dictadd Ascend-Receive-Secret 215 0 string
    ns_radius dictadd Ascend-IPX-Peer-Mode 216 0 integer
    ns_radius dictadd Ascend-IP-Pool-Definition 217 0 string
    ns_radius dictadd Ascend-Assign-IP-Pool 218 0 integer
    ns_radius dictadd Ascend-FR-Direct 219 0 integer
    ns_radius dictadd Ascend-FR-Direct-Profile 220 0 string
    ns_radius dictadd Ascend-FR-Direct-DLCI 221 0 integer
    ns_radius dictadd Ascend-Handle-IPX 222 0 integer
    ns_radius dictadd Ascend-Netware-timeout 223 0 integer
    ns_radius dictadd Ascend-IPX-Alias 224 0 integer
    ns_radius dictadd Ascend-Metric 225 0 integer
    ns_radius dictadd Ascend-PRI-Number-Type 226 0 integer
    ns_radius dictadd Ascend-Dial-Number 227 0 string
    ns_radius dictadd Ascend-Route-IP 228 0 integer
    ns_radius dictadd Ascend-Route-IPX 229 0 integer
    ns_radius dictadd Ascend-Bridge 230 0 integer
    ns_radius dictadd Ascend-Send-Auth 231 0 integer
    ns_radius dictadd Ascend-Send-Passwd 232 0 string
    ns_radius dictadd Ascend-Link-Compression 233 0 integer
    ns_radius dictadd Ascend-Target-Util 234 0 integer
    ns_radius dictadd Ascend-Maximum-Channels 235 0 integer
    ns_radius dictadd Ascend-Inc-Channel-Count 236 0 integer
    ns_radius dictadd Ascend-Dec-Channel-Count 237 0 integer
    ns_radius dictadd Ascend-Seconds-Of-History 238 0 integer
    ns_radius dictadd Ascend-History-Weigh-Type 239 0 integer
    ns_radius dictadd Ascend-Add-Seconds 240 0 integer
    ns_radius dictadd Ascend-Remove-Seconds 241 0 integer
    ns_radius dictadd Ascend-Data-Filter 242 0 string
    ns_radius dictadd Ascend-Call-Filter 243 0 string
    ns_radius dictadd Ascend-Idle-Limit 244 0 integer
    ns_radius dictadd Ascend-Preempt-Limit 245 0 integer
    ns_radius dictadd Ascend-Callback 246 0 integer
    ns_radius dictadd Ascend-Data-Svc 247 0 integer
    ns_radius dictadd Ascend-Force-56 248 0 integer
    ns_radius dictadd Ascend-Billing-Number 249 0 string
    ns_radius dictadd Ascend-Call-By-Call 250 0 integer
    ns_radius dictadd Ascend-Transit-Number 251 0 string
    ns_radius dictadd Ascend-Host-Info 252 0 string
    ns_radius dictadd Ascend-PPP-Address 253 0 ipaddr
    ns_radius dictadd Ascend-MPP-Idle-Percent 254 0 integer
    ns_radius dictadd Ascend-Xmit-Rate 255 0 integer

    # Cisco attributes
    ns_radius dictadd Cisco-AVPair 1 9 string
    ns_radius dictadd Cisco-Multilink-ID 187 9 integer
    ns_radius dictadd Cisco-Num-In-Multilink 188 9 integer
    ns_radius dictadd Cisco-Pre-Input-Octets 190 9 integer
    ns_radius dictadd Cisco-Pre-Output-Octets 191 9 integer
    ns_radius dictadd Cisco-Pre-Input-Packets 192 9 integer
    ns_radius dictadd Cisco-Pre-Output-Packets 193 9 integer
    ns_radius dictadd Cisco-Maximum-Time 194 9 integer
    ns_radius dictadd Cisco-Disconnect-Cause 195 9 integer
    ns_radius dictadd Cisco-Data-Rate 197 9 integer
    ns_radius dictadd Cisco-PreSession-Time 198 9 integer
    ns_radius dictadd Cisco-PW-Lifetime 208 9 integer
    ns_radius dictadd Cisco-IP-Direct 209 9 integer
    ns_radius dictadd Cisco-PPP-VJ-Slot-Comp 210 9 integer
    ns_radius dictadd Cisco-PPP-Async-Map 212 9 integer
    ns_radius dictadd Cisco-IP-Pool-Definition 217 9 integer
    ns_radius dictadd Cisco-Asing-IP-Pool 218 9 integer
    ns_radius dictadd Cisco-Route-IP 228 9 integer
    ns_radius dictadd Cisco-Link-Compression 233 9 integer
    ns_radius dictadd Cisco-Target-Util 234 9 integer
    ns_radius dictadd Cisco-Maximum-Channels 235 9 integer
    ns_radius dictadd Cisco-Data-Filter 242 9 integer
    ns_radius dictadd Cisco-Call-Filter 243 9 integer
    ns_radius dictadd Cisco-Idle-Limit 244 9 integer
    ns_radius dictadd Cisco-Xmit-Rate 255 9 integer

    # Livingston attributes
    ns_radius dictadd LE-Terminate-Detail 2 307 string
    ns_radius dictadd LE-Advice-of-Charge 3 307 string

    # RiverStone attributes
    ns_radius dictadd Riverstone-Command 1 5567 string
    ns_radius dictadd Riverstone-System-Event 2 5567 string
    ns_radius dictadd Riverstone-SNMP-Config-Change 3 5567 string
    ns_radius dictadd Riverstone-User-Level 4 5567 integer

    # Shiva attributes
    ns_radius dictadd Shiva-User-Attributes 51 166 string
    ns_radius dictadd Shiva-User-Attributes 1 166 string
    ns_radius dictadd Shiva-Called-Number 90 166 string
    ns_radius dictadd Shiva-Calling-Number 91 166 string
    ns_radius dictadd Shiva-Customer-Id 92 166 string
    ns_radius dictadd Shiva-Type-Of-Service 93 166 integer
    ns_radius dictadd Shiva-Link-Speed 94 166 integer
    ns_radius dictadd Shiva-Links-In-Bundle 95 166 integer
    ns_radius dictadd Shiva-Compression-Type 96 166 integer
    ns_radius dictadd Shiva-Link-Protocol 97 166 integer
    ns_radius dictadd Shiva-Network-Protocols 98 166 integer
    ns_radius dictadd Shiva-Session-Id 99 166 integer
    ns_radius dictadd Shiva-Disconnect-Reason 100 166 integer
    ns_radius dictadd Shiva-Acct-Serv-Switch 101 166 ipaddr
    ns_radius dictadd Shiva-Event-Flags 102 166 integer
    ns_radius dictadd Shiva-Function 103 166 integer
    ns_radius dictadd Shiva-Connect-Reason 104 166 integer

    # NetScreen attributes
    ns_radius dictadd NS-Admin-Privilege 1 3224 integer READ_WRITE 2 VSYS_ADMIN 3 READ_ONLY 4 VSYS_READ_ONLY 5
    ns_radius dictadd NS-Admin-Vsys-Name 2 3224 string
    ns_radius dictadd NS-User-Group 3 3224 string
    ns_radius dictadd NS-Primary-DNS-Server 4 3224 ipaddr
    ns_radius dictadd NS-Secondary-DNS-Server 5 3224 ipaddr
    ns_radius dictadd NS-Primary-WINS-Server  6 3224 ipaddr
    ns_radius dictadd NS-Secondary-WINS-Server 7 3224 ipaddr
    ns_radius dictadd NS-Version 8 3224 string
    ns_radius dictadd NS-PRO-User-Group 200 3224 string
    ns_radius dictadd NS-PRO-User-IKEID 201 3224 string
}

