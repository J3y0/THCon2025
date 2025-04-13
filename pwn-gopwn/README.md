# GoPwn !

### Description

#### French

Récemment, des rumeurs ont émergé sur le Dark Web, chuchotant à propos d’une faille secrète dans les systèmes du gouvernement. Une vulnérabilité qui permettrait d’accéder à des informations sensibles, menaçant de dévoiler des secrets qui pourraient faire basculer l’équilibre de la ville. Jhonny Jhon Jhonson, un jeune cadre dynamique de l’Aurora Initiative, semble en savoir plus qu’il ne le laisse entendre. Avec son influence au sein de l’organisation, il est l’un des seuls à avoir accès à ces données critiques et aux outils de gestion des infrastructures vitales de TH City.

En tant qu’agent de la S.N.A.F.U., vous êtes chargé de vérifier la véracité de ces rumeurs. Jhonny vous a confié la mission de tester la sécurité des systèmes de l’Aurora Initiative, mais son insistance sur l’étendue des dégâts qu’une telle vulnérabilité pourrait provoquer résonne profondément en vous. L'idée qu’une brèche dans leurs systèmes pourrait compromettre des infrastructures essentielles, ou pire, permettre à des forces extérieures de prendre le contrôle, vous fait froid dans le dos. Vous êtes déterminé à découvrir cette faille, coûte que coûte. L’avenir de la ville pourrait bien en dépendre.

#### English

Recently, rumors emerged on the Dark Web, whispering about a secret flaw in government systems. A vulnerability that would allow access to sensitive information, threatening to reveal secrets that could tip the balance of the city. Jhonny Jhon Jhonson, a dynamic young executive with the Aurora Initiative, seems to know more than he lets on. With his influence within the organization, he is one of the only people with access to this critical data and to the tools for managing TH City's vital infrastructure.

As an agent of the S.N.A.F.U., your job is to verify the truth of these rumors. Jhonny has entrusted you with the task of testing the security of the Aurora Initiative's systems, but his insistence on the extent of the damage such a vulnerability could cause resonates deeply with you. The idea that a breach in their systems could compromise critical infrastructure, or worse, allow outside forces to take control, sends a chill down your spine. You're determined to find the breach, whatever the cost. The future of the city may well depend on it.

### Write-Up
Follow [this link](./solve/writeup.md).

### Architecture

A simple socket server badly coded. A check is vulnerable to int overflow, allowing the user to proceed to buffer overflow in a second place. The user can then become an admin thanks to it.

### Attachments

Source code is given: `gopwn.go` and `Dockerfile`
