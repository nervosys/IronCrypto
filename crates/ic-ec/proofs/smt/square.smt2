; The squaring identity for a four-word number, over the integers:
;
;   sum_{i<j} 2 a_i a_j 2^(64 (i + j)) + sum_i a_i^2 2^(128 i) = (sum_i a_i 2^(64 i))^2
;
; A statement about polynomials, not about code: the six cross products
; doubled and the four squares, each at its weight, are the square.
; docs/PROOFS.md says how it joins the Kani proofs of P-256's `square`.
;
; The negation is asserted; `unsat` proves the identity, for every integer.

(set-logic QF_NIA)
(declare-const a0 Int) (declare-const a1 Int) (declare-const a2 Int) (declare-const a3 Int)

(define-fun w1 () Int 18446744073709551616)
(define-fun w2 () Int (* w1 w1))
(define-fun w3 () Int (* w2 w1))
(define-fun w4 () Int (* w3 w1))
(define-fun w5 () Int (* w4 w1))
(define-fun w6 () Int (* w5 w1))

(define-fun a () Int (+ a0 (* a1 w1) (* a2 w2) (* a3 w3)))

(define-fun cross () Int
  (+ (* a0 a1 w1) (* a0 a2 w2) (* a0 a3 w3)
     (* a1 a2 w3) (* a1 a3 w4)
     (* a2 a3 w5)))

(define-fun diagonal () Int
  (+ (* a0 a0) (* a1 a1 w2) (* a2 a2 w4) (* a3 a3 w6)))

(assert (not (= (+ (* 2 cross) diagonal) (* a a))))
(check-sat)
