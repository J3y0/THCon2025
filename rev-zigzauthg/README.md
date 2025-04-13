# ZigZAuth'g!

### Description

#### French

Viktor est un maître du camouflage numérique. Connu pour sa capacité à manipuler des réseaux cachés et à communiquer dans l'ombre, il a mis en place un portail d’authentification ultra-sécurisé pour protéger ses informations les plus sensibles. Ce portail est la clé d'accès à ses réseaux privés, où il planifie les actions de sabotage contre les autorités de TH City.

Vous avez été assigné par l'équipe du S.N.A.F.U. pour infiltrer ce portail et récupérer les informations nécessaires pour localiser ses prochaines cibles et déjouer ses plans.

Votre mission :
- Pénétrer dans le système d’authentification.
- Extraire les données critiques concernant les opérations secrètes de Viktor et des informations sur ses complices.

Montrez que vous pouvez percer le mystère de ce portail et empêcher les ombres de recouvrir complètement la ville.
Bonne chance, agent.

Le sha256 du binaire téléchargé est: `sha256(zigzauthg) = ba0aeda51612f272f9dfeb1185ff4e66e84eb2ced6c9dc8a829b22ece79d208f`

#### English

Viktor is a master of digital camouflage. Known for his ability to manipulate hidden networks and communicate in the shadows, he has set up an ultra-secure authentication portal to protect his most sensitive information. This portal is the key to access his private networks, where he plans sabotage actions against the TH City authorities.

You've been assigned by the S.N.A.F.U. team to infiltrate this portal and retrieve the information needed to locate his next targets and foil his plans.

Your mission:
- Penetrate the authentication system.
- Extract critical data on Viktor's secret operations and information on his accomplices.

Show that you can unravel the mystery of this portal and prevent the shadows from completely covering the city.
Good luck, agent.


### Writeup
Follow [this link](./solve/writeup.md).

### Architecture

This challenge aims at reversing a simple auth portal written in Zig. All the complexity comes from
th zig language itself as it generates many checks under the hood that add many operations to the assembly code.
This is why, even a simple program can be hard to decompile in the existing decompiler.

The goal is to understand a little better how Zig works and to bring something new to C reverse engineering.

### Attachment

The binary `ZigZauth'g`
