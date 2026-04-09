# CRC

# D'où il vient ?

Le CRC est un calcule fait à partir du packet : crc = binascii.crc_hqx(packet, 0xFFFF)

# A quoi il sert ?

Il sert à savoir si oui ou non le packet à été altéré ou pas. Comment ? Lorsque le recepteur reçoit le paquet, il récupère le CRC et recalcule la trame. S'il retombe sur le même CRC la trame n'a pas été alteré sinon si

# Par quoi a-t'il pu être altéré ?

Par le bruit, ou par un attaquant

# Peut-on savoir à 100% si le CRC a été altéré ?

Non, il se peut que le CRC et le paquet on été altéré et que miraculeusement lorsqu'on recalcule le packet on retombe sur le CRC, ce qui est très très rare, cependant il existe une probabilité de collision, pour un CRC-16 c'est ~1/65536.
Ou bien un attaquant peut se intercepter la trame, changer le paquet et y placer son propre CRC calculé sur la trame modifié par l'attaquant.

# Comment s'en protéger ?

Pour s'en protéger contre des attaques, il faut un mécanisme d’intégrité/authentification cryptographique (ex. MAC ou signature), pas un CRC.
