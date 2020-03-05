# Open Enclave SDL Bug Bar

The information listed in this “bug bar” is intended to help Open Enclave SDK developers to triage bugs and determine the bug severity in terms of security. 

This bug bar and the ratings are derived based on [Microsoft SDL Bug bar](https://aka.ms/sdlbugbar) to apply for the enclaves, specifically to the enclaves created using Intel SGX technology. It is highly recommended to fix all known bugs with critical, important, or moderate severity prior to release. 

The bug bar describes different severities for the bugs affecting enclaves. Enclaves are the privileged execution environment which is a security domain. There is a security boundary between enclave and rest of the system, this is a stronger security boundary that should be defended. It is important to understand the enclave security boundary, it should be apt to consider this as a confidentiality & integrity boundary. Anything that is inside enclave should never be accessible or modified from outside of the enclave. 

Enclave security boundary is quite interesting, everything that is outside this boundary is adversarial which can fully control the existence of the enclave but can’t access or modify the data over inside the enclave crossing the enclave security boundary. Things that are outside the enclave security boundary are the current application, other enclaves, OS kernel, VMM/Hypervisor & SMM. Except the CPU everything is untrusted for enclaves. 


## Enclave – Vulnerability Type Pivot 
-------------------------------------

* ### Spoofing
	**Critical**
    * A malicious enclave spoofs the identity of a victim enclave
  	
    -------------

* ### Tampering	
    **Critical**
    * Any modification of enclave code or data by untrusted entity
     
        Note: This vulnerability can also lead to memory corruption in which case we should triage this as Elevation of Privilege bug. The distinction to make here is that the vulnerability is allowing an attacker to modify enclave code or data without getting noticed 

            Examples:
            •	Tampering the enclave image in plain text and keep the measurements same
    
    -------------

* ### Repudiation
    * N/A

            Repudiation threats are associated with users who deny performing an action without other parties having any way to prove otherwise. This is not applicable in the context of enclave as it is against the confidential security property of enclave to track against user actions within enclave context.
            
    -------------

* ### Information Disclosure
    **Critical**
    * Any cases where the attacker can bypass the enclave security boundary to read arbitrary information belonging to an enclave that was not intended or designed to be exposed

            Examples:
            •	Unintentional read access to memory contents in enclave space from outside (application, OS kernel, Hypervisor)

    **Important**
	* Disclosing enclave memory contents outside the enclave security boundary. In this case attacker doesn't control what data is being leaked

            Examples:
            •	OCALLS passing uninitialized memory from enclave to outside	
    -----------

* ### Denial of Service
	* N/A

            Enclave threat model doesn’t protect against DoS. Since the enclave execution is under the adversarial control, which is the host OS, the threat model assumes the host OS to be untrusted, so DoS attacks are unprotected.

    -----------

* ### Elevation of Privilege	
    **Critical**
    * Any cases where an attacker can bypass the security boundary and execute arbitrary code within an enclave context

            Examples:
            •	Attacker able to invoke any executable code other than enclave entry points

    * All exploitable write AVs (Access Violations), integer overflows and other crashes

            Examples:
            •	Any memory corruption bug within enclave that can be triggered from an attacker outside of the enclave	
        
    **Important**
	* Access to untrusted memory in an unsafe manner

            Examples:
            •	Any untrusted memory that is accessed multiple times (multiple fetch) without copying it to enclave memory

    * Executing non-enclave code in the context of an enclave thread
    
    * Invoking enclave interface without proper initialization 

            Examples:
            •	Attacker able to invoke enclave functions on a different enclave thread while the initialization is happening on a thread that is handling exception
            •	Any cases where an attacker can spoof the return from OCALL 	
        
    ------------
