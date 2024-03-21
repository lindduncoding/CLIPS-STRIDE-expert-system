;;;======================================================
;;;  	STRIDE/Information Security Expert System
;;;
;;;     This expert system helps determine which category
;;;     of the STRIDE method a cyber attack falls into
;;;	and give mitigation steps based on that.
;;;
;;;     Fidelya Fredelina 22/496507/TK/54405
;;;
;;;     To execute, merely load, reset and run.
;;;======================================================

;; Define Functions

(deffunction member (?item $?list)
   (if (member$ ?item ?list)
      then
      (return TRUE)
      else
      (return FALSE)
   )
)

(deffunction next-question (?question ?allowed-values)
   (printout t ?question crlf)
   (printout t "Answer: ")
   (bind ?reply (read))
   (printout t crlf)
   (if (numberp ?reply)
       then
           (if (member ?reply ?allowed-values)
               then
                   (bind ?reply ?reply)
               else
                   (bind ?reply ""))
       else
           (bind ?reply ""))
   
   (while (not (numberp ?reply)) do
      (printout t ?question crlf)
      (printout t "Please enter a valid number reply. ")
      (bind ?reply (read))
      (printout t crlf)
      
      (if (numberp ?reply)
          then
              (if (member ?reply ?allowed-values)
                  then
                      (bind ?reply ?reply)
                  else
                      (bind ?reply ""))
          else
              (bind ?reply "")))
   
   ?reply
)

;; Initialization

(defrule start
  (declare (salience 10000))
  =>
  (set-fact-duplication TRUE)
  (printout t "" crlf)
  (printout t "Welcome to the improved STRIDE Expert System. We will give facts and you will answer acordingly." crlf)
  (printout t "" crlf)
  (printout t "Accepted replies:" crlf)
  (printout t "-------------------------------------" crlf)
  (printout t " Value           Meaning " crlf)
  (printout t "-------------------------------------" crlf)
  (printout t " -1              Definitely Not "	crlf)
  (printout t " -0.8            Almost certainly not "	crlf)
  (printout t " -0.6            Probably not "	crlf)
  (printout t " -0.4            Maybe not "	crlf)
  (printout t "  0              Unknown "	crlf)
  (printout t "  0.4            Maybe "	crlf)
  (printout t "  0.6            Probably "	crlf)
  (printout t "  0.8            Almost certainly "	crlf)
  (printout t "  1              Definitely "	crlf)
  (printout t "-------------------------------------" crlf)
  (printout t "" crlf))

;; Define Form of Fact: consisting of fact and certainty factor

(deftemplate a-fact
   (slot name)
   (slot cf (default 0.0)))

;; Durkin Rules

(defrule combine-certainties-1 (declare (salience 100)(auto-focus TRUE))
  ?fact1 <- (a-fact (name ?id) (cf ?cf1))
  ?fact2 <- (a-fact (name ?id) (cf ?cf2))
  (test (neq ?fact1 ?fact2))
  (test (> ?cf1 0))
  (test (> ?cf2 0))
  =>
  (retract ?fact1)
  (modify ?fact2 (cf (+ ?cf1 (* ?cf2 (- 1 ?cf1))))))

(defrule combine-certainties-2 (declare (salience 100)(auto-focus TRUE))
  ?fact1 <- (a-fact (name ?id) (cf ?cf1))
  ?fact2 <- (a-fact (name ?id) (cf ?cf2))
  (test (neq ?fact1 ?fact2))
  (test (< ?cf1 0))
  (test (< ?cf2 0))
  =>
  (retract ?fact1)
  (modify ?fact2 (cf (+ ?cf1 (* ?cf2 (+ 1 ?cf1))))))

(defrule combine-certainties-3 (declare (salience 100)(auto-focus TRUE))
  ?fact1 <- (a-fact (name ?id) (cf ?cf1))
  ?fact2 <- (a-fact (name ?id) (cf ?cf2))
  (test (neq ?fact1 ?fact2))
  (test (> ?cf1 0))
  (test (< ?cf2 0))
  =>
  (retract ?fact1)
  (modify ?fact2 (cf (/ (+ ?cf1 ?cf2) (- 1 (min (abs ?cf1) (abs ?cf2)))))))


;; Define Template for Question: consisting of fact, question name, and is it asked already

(deftemplate question
   (slot a-fact (default ?NONE))
   (slot the-question (default ?NONE))
   (slot already-asked (default FALSE)))

;; Rule for asking a question: making sure only the accepted replies are assesed.

(defrule ask-question
   ?f <- (question (already-asked FALSE)
                        (the-question ?the-question)
                        (a-fact ?the-fact))
   =>
   (modify ?f (already-asked TRUE))
   (bind ?accepted (create$ -1 -0.8 -0.6 -0.4 0 0.4 0.6 0.8 1))
   (assert (a-fact (name ?the-fact) (cf (next-question ?the-question ?accepted)))))

;; List of Questions

(deffacts questionnaire-facts
  (question (a-fact pass-breached)
                 (the-question "There was a case in my organization where a password of a user is breached. "))
  (question (a-fact root)
                 (the-question "The root password was once breached. "))
  (question (a-fact login-unknown)
                 (the-question "There was a case where someone unknown logged into our organization. "))
  (question (a-fact phising)
                 (the-question "Someone tried to impersonate our organization before. "))
  (question (a-fact access-unknown)
                 (the-question "The database was accessed from an unknown location/device. "))
  (question (a-fact modify)
                 (the-question "The system (data, cookie, cache, etc) was modified from an unauthorized account. "))
  (question (a-fact continuous-req)
                 (the-question "There were suspicious connection repeatedly requesting the server. "))
  (question (a-fact server-down)
                 (the-question "The server is currently down. "))
  (question (a-fact log)
                 (the-question "We have an access log that monitors the network. "))
  (question (a-fact deny)
                 (the-question "When confronted, the attacker denied involvement in the attack. ")))

;; Rules (for complex facts)

(defrule is-compromised
  ?fact1 <- (a-fact (name pass-breached) (cf ?cf1))
  ?fact2 <- (a-fact (name login-unknown) (cf ?cf2))
  =>
  (assert (a-fact (name compromised-login) (cf (* (max ?cf1 ?cf2) 0.7))))
  (assert (a-fact (name compromised-root) (cf (* (max ?cf1 ?cf2) 0.3))))
)

(defrule is-root-compromised
  ?fact1 <- (a-fact (name compromised-login) (cf ?cf1))
  ?fact2 <- (a-fact (name root) (cf ?cf2))
  =>
  (assert (a-fact (name compromised-root) (cf (* (min ?cf1 ?cf2) 1))))
)

(defrule is-access-granted
  ?fact1 <- (a-fact (name access-unknown) (cf ?cf1))
  ?fact2 <- (a-fact (name compromised-login) (cf ?cf2))
  =>
  (assert (a-fact (name access-granted) (cf (* (max ?cf1 ?cf2) 0.6))))
  (assert (a-fact (name modify) (cf (* (max ?cf1 ?cf2) 0.4))))
)

(defrule is-denial
  ?fact1 <- (a-fact (name access-granted) (cf ?cf1))
  ?fact2 <- (a-fact (name deny) (cf ?cf2))
  =>
  (assert (a-fact (name denial) (cf (* (min ?cf1 ?cf2) 0.8))))
  (assert (a-fact (name log) (cf (* (min ?cf1 ?cf2) -0.8))))
)

;; Rules (for STRIDE identification)

(defrule is-spoofing
  ?fact1 <- (a-fact (name compromised-login) (cf ?cf1))
  ?fact2 <- (a-fact (name phising) (cf ?cf2))
  =>
  (assert (a-fact (name spoofing) (cf (* (max ?cf1 ?cf2) 0.8))))
)

(defrule is-tampering
  ?fact1 <- (a-fact (name access-granted) (cf ?cf1))
  ?fact2 <- (a-fact (name modify) (cf ?cf2))
  =>
  (assert (a-fact (name tampering) (cf (* (min ?cf1 ?cf2) 0.6))))
)

(defrule is-repudiation-denial
  ?fact1 <- (a-fact (name denial) (cf ?cf1))
  =>
  (assert (a-fact (name repudiation) (cf (* ?cf1 0.7))))
)

(defrule is-repudiation-log
  ?fact1 <- (a-fact (name log) (cf ?cf1))
  =>
  (assert (a-fact (name repudiation) (cf (* ?cf1 0.7))))
)

(defrule is-info-disclosure
  ?fact1 <- (a-fact (name access-granted) (cf ?cf1))
  =>
  (assert (a-fact (name info-disclosure) (cf (* ?cf1 0.7))))
)

(defrule is-dos
  ?fact1 <- (a-fact (name server-down) (cf ?cf1))
  ?fact2 <- (a-fact (name continuous-req) (cf ?cf2))
  =>
  (assert (a-fact (name dos) (cf (* (min ?cf1 ?cf2) 0.9))))
)

(defrule is-priv-elevation
  ?fact1 <- (a-fact (name compromised-root) (cf ?cf1))
  =>
  (assert (a-fact (name priv-elevation) (cf (* ?cf1 0.9))))
)

;; Mitigation Rules

(defrule print-results
  =>
  (printout  t "We detected that your threats fall under the categories of:" crlf)
  (printout  t crlf)
  (assert (finished)))

(defrule spoofing
  (finished)
  (a-fact (name spoofing) (cf ?cf1))
  =>
  (if (>= ?cf1 0.4) 
      then
      (printout  t "Spoofing with certainty: " ?cf1 crlf)
      (printout  t "Here are some tips: implement strong password policies, use multifactor authentication, improve access control/authentication methods." crlf)
      (printout  t crlf)))

(defrule tampering
  (finished)
  (a-fact (name tampering) (cf ?cf1))
  =>
  (if (>= ?cf1 0.4) 
      then
      (printout  t "Tampering with certainty: " ?cf1 crlf)
      (printout  t "Here are some tips: improve authentication methods, check for bad characters to prevent SQL injection, encrypt data on transit." crlf)
      (printout  t crlf)))

(defrule repudiation
  (finished)
  (a-fact (name repudiation) (cf ?cf1))
  =>
  (if (>= ?cf1 0.4) 
      then
      (printout  t "Repudiation with certainty: " ?cf1 crlf)
      (printout  t "Here are some tips: implement digital signature, implement robust logging and auditing mechanism." crlf)
      (printout  t crlf)))

(defrule info-disclosure
  (finished)
  (a-fact (name info-disclosure) (cf ?cf1))
  =>
  (if (>= ?cf1 0.4) 
      then
      (printout  t "Information Disclosure with certainty: " ?cf1 crlf)
      (printout  t "Here are some tips: utilize encryption and hashing to secure confidential information, improve authentication methods." crlf)
      (printout  t crlf)))

(defrule dos
  (finished)
  (a-fact (name dos) (cf ?cf1))
  =>
  (if (>= ?cf1 0.4) 
      then
      (printout  t "Denial of Service with certainty: " ?cf1 crlf)
      (printout  t "Here are some tips: blocks connection/IP after N continuous requests, utilize captcha tests to prevent bots." crlf)
      (printout  t crlf)))

(defrule priv-elevation
  (finished)
  (a-fact (name priv-elevation) (cf ?cf1))
  =>
  (if (>= ?cf1 0.4) 
      then
      (printout  t "Elevation of Privilege with certainty: " ?cf1 crlf)
      (printout  t "Here are some tips: run with the least privilege, utilize strong root password, check for vulnerabilities and update system often." crlf)
      (printout  t crlf)))
