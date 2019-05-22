from CryptoUtil import CryptoUtil
from wallet import wallet

pk = 'b20390e004ba809fbef7dac28e26bd94705b1a8e67444ac9ab38259cdab7b9551c075a127d7343789d0e39c4b5152f7df97669f302f34e46a386140c9b57f899'
sk = '42344d25a58c8ac14aee23607d79ad2190553869f4f61ceeb056b3255f6c3012'

data = "test"
c = CryptoUtil(pk, sk)
sig = c.sign(data)

ret = CryptoUtil.verify(CryptoUtil,pk, sig, data)

print(ret)


