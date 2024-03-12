;;;======================================================
;;;  	STRIDE/Information Security Expert System
;;;
;;;     This expert system helps determine which category
;;;     of the STRIDE method a cyber attack falls into
;;;	by asking a bunch of yes-no questions to the user
;;;	and give mitigation steps based on that.
;;;
;;;     Fidelya Fredelina 22/496507/TK/54405
;;;
;;;     To execute, merely load, reset and run.
;;;======================================================

;;;*******************
;;;* COMPLEX RULES *
;;;*******************

(defrule is-compromised
   (or (pass_breached yes)
       (login_unknown yes))
    => (assert (compromised_login yes)))

(defrule is-root-compromised
   (and (compromised_login yes)
       (root yes))
    => (assert (compromised_root yes)))

(defrule is-access-gained
   (or (access_unknown yes)
       (compromised_login yes))
    => (assert (gain_access yes)))

(defrule is-denial
   (and (gain_access yes)
       (deny yes))
    => (assert (denial yes)))

;;;*************************
;;;* STRIDE IDENTIFICATION *
;;;*************************

(defrule is-spoofing
   (or (compromised_login yes)
       (phising yes))
    => (assert (spoofing yes)))

(defrule is-tampering
   (and (gain_access yes)
       (modify yes))
    => (assert (tampering yes)))

(defrule is-repudiation
   (or (denial yes)
       (log no))
    => (assert (repudiation yes)))

(defrule is-info-disclosure
   (gain_access yes)
    => (assert (info_disclosure yes)))

(defrule is-dos
   (and (server_down yes)
       (continuous_req yes))
    => (assert (dos yes)))

(defrule is-priv-elevation
   (compromised_root yes)
    => (assert (priv_elevation yes)))

;;;**************
;;;* MITIGATION *
;;;**************

(defrule spoofing-mitigation
   (spoofing yes)
    => (printout t crlf "Oh no, you have been SPOOFED. Here are some tips: implement strong password policies, use multifactor authentication, improve access control/authentication methods."))

(defrule tampering-mitigation
   (tampering yes)
    => (printout t crlf "Something has been TAMPERED. Here are some tips: improve authentication methods, check for bad characters to prevent SQL injection, encrypt data on transit."))

(defrule repudiation-mitigation
   (repudiation yes)
    => (printout t crlf "The hacker DENIED involvement (also known as REPUDIATION). Here are some tips: implement digital signature, implement robust logging and auditing mechanism."))

(defrule info-disclosure-mitigation
   (info_disclosure yes)
    => (printout t crlf "Critical information has been DISCLOSED. Here are some tips: utilize encryption and hashing to secure confidential information, improve authentication methods."))

(defrule dos-mitigation
   (dos yes)
    => (printout t crlf "You've been DOS'd. Here are some tips: blocks connection/IP after N continuous requests, utilize captcha tests to prevent bots."))

(defrule priv-elevation-mitigation
   (priv_elevation yes)
    => (printout t crlf "Attacker ELEVATED PRIVILEGE. Here are some tips: run with the least privilege, utilize strong root password, check for vulnerabilities and update system often."))

;;;*********
;;;* INPUT *
;;;*********

(defrule input
   =>
   (printout t crlf "Welcome to the STRIDE expert system. Just answer yes/no to our questions.")
   (printout t crlf "Is there a case in your organization where a password of a user is breached?")
   (assert (pass_breached = (read)))
   (printout t crlf "Is the account breached a root/admin user?")
   (assert (root = (read)))
   (printout t crlf "Is there a case where someone logged in to a user account from an unknown device/location?")
   (assert (login_unknown = (read)))
   (printout t crlf "Have you ever got a message where someone impersonate a legit user from your organization?")
   (assert (phising = (read)))
   (printout t crlf "Is there a case where a database or the system is accessed from an unknown device/location?")
   (assert (access_unknown = (read)))
   (printout t crlf "Is there a case where the system (data, cookie, cache, etc) is modified from an unauthorized account?")
   (assert (modify = (read)))
   (printout t crlf "Is your server currently down?")
   (assert (server_down = (read)))
   (printout t crlf "Are there suspicious IP addresses connecting and requesting to the server continously?")
   (assert (continuous_req = (read)))
   (printout t crlf "Do you have an access log?")
   (assert (log = (read)))
   (printout t crlf "Is the attacker ever denied they were involved in an attack?")
   (assert (deny = (read)))
   (printout t crlf "From the facts above, we identify that this threat is considered: " crlf))