; The schoolbook identity for a four-word product, over the integers:
;
;   sum_{i,j < 4} a_i b_j 2^(64 (i + j)) = (sum_i a_i 2^(64 i)) (sum_j b_j 2^(64 j))
;
; A statement about polynomials, not about code: it says that summing the
; sixteen word products at their weights is multiplying the two numbers.
; docs/PROOFS.md says how it joins the Kani proofs of P-256's `mul`.
;
; The negation is asserted; `unsat` proves the identity. No bound is put on
; the a_i and b_j: it holds for every integer, so for every word.

(set-logic QF_NIA)
(declare-const a0 Int) (declare-const a1 Int) (declare-const a2 Int) (declare-const a3 Int)
(declare-const b0 Int) (declare-const b1 Int) (declare-const b2 Int) (declare-const b3 Int)

; 2^64, and its powers by repeated multiplication of the constant.
(define-fun w1 () Int 18446744073709551616)
(define-fun w2 () Int (* w1 w1))
(define-fun w3 () Int (* w2 w1))
(define-fun w4 () Int (* w3 w1))
(define-fun w5 () Int (* w4 w1))
(define-fun w6 () Int (* w5 w1))

(define-fun a () Int (+ a0 (* a1 w1) (* a2 w2) (* a3 w3)))
(define-fun b () Int (+ b0 (* b1 w1) (* b2 w2) (* b3 w3)))

(define-fun schoolbook () Int
  (+ (* a0 b0)        (* a0 b1 w1)    (* a0 b2 w2)    (* a0 b3 w3)
     (* a1 b0 w1)     (* a1 b1 w2)    (* a1 b2 w3)    (* a1 b3 w4)
     (* a2 b0 w2)     (* a2 b1 w3)    (* a2 b2 w4)    (* a2 b3 w5)
     (* a3 b0 w3)     (* a3 b1 w4)    (* a3 b2 w5)    (* a3 b3 w6)))

(assert (not (= schoolbook (* a b))))
(check-sat)
