from CryptoUtil import CryptoUtil


pk = 'c616463ef6d433438ad26d958d4380311cae69b8603bffbec7f09e764f0d656685852f349cad97858c22849d294e39d7dc20fda56a60e16be6c4cce8f1b7d1bc'
sk = '38ebbd89405fd35cdab09ded677bead0662e886bb301a390e48e8887c0020bbb'

data = "test"
c = CryptoUtil(pk,sk)
sig = c.sign(data)
print(sig)

ret = c.verify(pk, sig, data)
print(ret)


