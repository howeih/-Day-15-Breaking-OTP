#Day 15: Breaking OTP

Sometimes I read that one-time pad is an unbreakable cipher. And of course, completely broken example is usually attached.
<br/>
The problem is, people confuse the definition of perfect cipher for unbreakable. If the cipher is perfect (according to Shannon), the probability distribution of obtaining cipher-text instance from different plain-texts must be uniform. In other words, given some cipher-text there is an equal chance for any plain-text to be the source.
<br/>
What follows is that adversary with infinite computational power can’t get any information about plain-text from pure cipher-text.
<br/>
But that’s far from unbreakable. Even correctly used OTP can be easily broken. Imagine a bank that would encrypt a digital checks with OTP, how easy would it be to rewrite $100.00 to $999.99 at well-known check position?
<br/>
Is OPT a perfect cipher? Not in most implementations. While people emphasize the single use of key, they also forget about the uniformity of key distribution which is as important.
<br/>
When I generated my messages I violated the one-time rule. The consequences are inevitable.

Ciphertext output::
<pre>
["take?this kiss upon?t", "and ?n parting from?y", "thus?much let me av?w", "you ?re not wrong w?o", "that?my days have b?e", "yet ?f hope has flo?n", "in a?night or in a ?a", "in a?vision or in n?n", "is i? therefore the?l", "all ?hat we see or ?e", "is b?t a dream with?n", "i st?nd amid the ro?r", "of a?surf tormented?s", "and ? hold within m? ", "grai?s of the golde? ", "how ?ew yet how the? ", "thro?gh my fingers ?o", "whil? i weep while ? ", "  ed?ar allan poe  ? "]
</pre>
