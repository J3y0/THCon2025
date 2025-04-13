# 10^{-9} mites !

### Description

#### French

Dans le monde cyberpunk de TH City, la technologie a franchi des frontières inimaginables, et l'une des innovations les plus secrètes de l'Aurora Initiative repose sur les nanomites. Ces minuscules dispositifs sont des machines microscopiques capables de s’infiltrer dans des systèmes complexes à un niveau aussi profond que les processeurs eux-mêmes. Mais les nanomites ne servent pas seulement à manipuler ou réparer des systèmes — elles sont aussi utilisées pour créer des mécanismes de protection ultra-avancés.

Ces nanomites peuvent détecter toute tentative d’analyse parait-il. Il serait alors impossible de les debugger.

Ce niveau de sécurité être inviolable. Un fichier récemment intercepté révèle que des nanomites ont été implantées dans des systèmes critiques pour contrer toute tentative de rétro-ingénierie ou d'interception des données sensibles.

Vous avez entre les mains un échantillon du programme infecté par ces nanomites. Le défi est simple : contourner leurs mécanismes de protection et découvrir les secrets qu'elles dissimulent. Mais attention, votre mission n'est pas anodine. En tant que jeune recru de la S.N.A.F.U., on vous teste sur cette avancée technologique. Prouvez que ces nanomites ne sont pas infaillibles, en neutralisant leur système de protection et en récupérant les informations cachées à l'intérieur.

Le sha256 du binaire téléchargé est: `sha256(nano_mites) = 9f02f6f15eca52f07e481a6f6f2c6b83ecb2cf42e6bc98aa45cb48a0dfbc2931`

#### English

In the cyberpunk world of TH City, technology has crossed unimaginable boundaries, and one of the Aurora Initiative's most secret innovations is nanomites. These tiny devices are microscopic machines capable of infiltrating complex systems at a level as deep as the processors themselves. But nanomites aren't just used to manipulate or repair systems - they're also used to create ultra-advanced protection mechanisms.

These nanomites can apparently detect any attempt at analysis. It would then be impossible to debug them.

This level of security would be unbreakable. A recently intercepted file reveals that nanomites have been implanted in critical systems to counter any attempt to reverse-engineer or intercept sensitive data.

You have in your hands a sample of the program infected by these nanomites. The challenge is simple: bypass their protection mechanisms and discover the secrets they conceal. But beware, your mission is not a trivial one. As a young S.N.A.F.U. recruit, you'll be tested on this technological breakthrough. Prove that these nanomites are not infallible, by neutralizing their protection system and recovering the information hidden inside.

The sha256 of the downloaded binary is: `sha256(nano_mites) = 9f02f6f15eca52f07e481a6f6f2c6b83ecb2cf42e6bc98aa45cb48a0dfbc2931`

### Write-Up
Follow [this link](./solve/writeup.md).

### Architecture
The challenge aims at reversing a packer application which is protected by nanomites. This technique prevents
challengers from analyzing the child process dynamically as it would be traced already by the father process.

### Attachments
A simple binary will be given.

