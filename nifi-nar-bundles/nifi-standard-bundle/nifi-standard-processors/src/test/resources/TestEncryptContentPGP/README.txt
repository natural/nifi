  592  2019-11-14 17:16:06 gpg --homedir  ~/var/somekeys/ -a --export-secret-keys A6DD9CE7BD9F355AF98CBEDAD773C35376D4C633 > /tmp/elgamal-private-ascii
  594  2019-11-14 17:16:21 gpg --homedir  ~/var/somekeys/ -a --export-secret-subkeys A6DD9CE7BD9F355AF98CBEDAD773C35376D4C633 > /tmp/elgamal-private-ascii
  607  2019-11-15 09:59:24 gpg --homedir /tmp/testkeys --full-generate-key EXAMPLE
  608  2019-11-15 10:00:35 gpg --homedir /tmp/testkeys -a --export rsa_rsa_example 
  609  2019-11-15 10:00:46 gpg --homedir /tmp/testkeys -a --export rsa_rsa_example > rsa_rsa_example.pub
  610  2019-11-15 10:01:07 gpg --homedir /tmp/testkeys -a --export-secret-keys rsa_rsa_example
  611  2019-11-15 10:01:17 gpg --homedir /tmp/testkeys -a --export-secret-keys rsa_rsa_example > rsa_rsa_example.priv
  616  2019-11-15 10:26:12 gpg --homedir /tmp/testkeys -a --export-secret-keys rsa_rsa_example > rsa_sign_rsa_encrypt.priv
  617  2019-11-15 10:26:28 gpg --homedir /tmp/testkeys -a --export rsa_rsa_example > rsa_sign_rsa_encrypt_example.pub
  624  2019-11-15 10:48:33 gpg --homedir /tmp/testkeys -a --export-secret-keys dsa_sign_no_encrypt
  627  2019-11-15 11:00:13 gpg --homedir /tmp/testkeys -a --export-secret-keys dsa_sign_no_encrypt > dsa_sign_no_encrypt.priv
  628  2019-11-15 11:00:18 gpg --homedir /tmp/testkeys -a --export dsa_sign_no_encrypt > dsa_sign_no_encrypt.pub
  629  2019-11-15 11:00:27 gpg --homedir /tmp/testkeys -a --export-secret-subkeys dsa_sign_elgamal_encrypt > dsa_sign_elgamal_encrypt.priv
  630  2019-11-15 11:00:36 gpg --homedir /tmp/testkeys -a --export dsa_sign_elgamal_encrypt > dsa_sign_elgamal_encrypt.pub
  633  2019-11-15 11:10:53 gpg --homedir /tmp/testkeys --full-generate-key
  634  2019-11-15 11:11:38 gpg --homedir /tmp/testkeys -a --export rsa_sign_no_encrypt > rsa_sign_no_encrypt.pub
  635  2019-11-15 11:11:59 gpg --homedir /tmp/testkeys -a --export-secret-keys rsa_sign_no_encrypt > rsa_sign_no_encrypt.priv
  638  2019-11-15 11:27:55 history |grep gpg
  639  2019-11-15 11:28:18 history |grep gpg |tail -n 20
  640  2019-11-15 11:28:28 history |grep gpg |tail -n 20 > README.txt
