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

### commentaires :

la deep packet analysis du mode default n'est pas infaillible et il se peut qu'elle ne reconnaisse pas certains paquets correctement.

Le mode follow TCP stream est encore en beta et n'implémente pas le traçage du numéro de séquence et d'acknowledgment. Toutes mes tentatives pour m'en servir ont échoué a ce jour.

### architecture :

Ce programme est composé de plusieurs classes, une par protocole. Les classes des protocoles situés aux couches supérieures héritent de celles des couches inférieures (ex : la classe TCPPacket hérite de la classe IPPacket).

On y retrouve également des classes utilitaires : PcapReader qui transforme un fichier .pcap en liste de paquets, PacketHandler qui regroupe toutes les classes de vérification et de transformation des packets, et enfin Options qui sert juste a l'option follow tcp stream.

Il y a 4 classes comprenant un main, Main qui est le main a run pour l'option -p, Main2 pour -t et Main3 pour le mode classique. Bien-sûr vous n'avez pas a changer de main puisque le main de la classe LineFish choisit automatiquement le bonne classe a run.