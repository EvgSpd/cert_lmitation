cd /d %CD%
rem python cert_limitation.py
python cert_limitation.py --mincifry Russian_Trusted_Root_CA.cer
rem python cert_limitation.py --mincifry Russian_Trusted_Root_CA.cer --root-key ./my_root_ca.key --root-cert ./my_root_ca.crt
pause