# LINEFISH

La classe a executer pour le main est LineFish :

>java LineFish \<filename> \<args>

le default quand on ne met pas d'argument parse le fichier .pcap et print les paquets selon une analyse en profondeur
### args :
>-t \<number> 

pour effectuer un follow tcp stream du packet a la ligne number (faites tourner le programme sans options avant pour voir ce qui vous interresse)

>-p

Cheat mode : le programme utilise les ports standards pour avoir une meilleure idée de quel protocole il s'agit

### version :

La version de java utilisée est la JDK 23.0.1