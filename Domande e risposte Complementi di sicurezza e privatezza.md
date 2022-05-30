# Risposte Complementi di sicurezza e privatezza

## 1 - Si richiede di descrivere le caratteristiche principali del modello access matrix. In particolare, descrivere come viene modellato lo stato del sistema e le operazioni primitive che modellano i cambiamenti di stato
Il modello Access Matrix fornisce un framework per descrivere sistemi di protezione. Spesso è riportato con il nome di modello HRU (Harrison, Ruzzo, Ullmann). Viene più comunemente chiamato con il nome Access Matrix in quanto lo stato di autorizzazione viene rappresentato con una matrice. Lo stato del sistema è definito con la tripla (S, O, A) dove:
- **S** è l'insieme dei soggetti (chi può esercitare i privilegi)
- **O** è l'insieme degli oggetti (su cui si esercitano i privilegi), i soggetti possono essere considerati come degli oggetti, in tal caso abbiamo che **S ⊆ O**
- **A** è la Access Matrix dove:
	- le righe corrispondono ai soggetti
	- le colonne corrispondono agli oggetti
	- **A[*s*,*o*]** riporta i privilegi di *s* sull'oggetto *o*
I cambiamenti di stato sono modellati attraverso operazioni primitive:
- **enter** *r* into **A[*s*,*o*]**: aggiunge il privilegio *r* per il soggetto *s* sull'oggetto *o*
- **delete** *r* from **A[*s*,*o*]**: rimuove il privilegio *r* per il soggetto *s* sull'oggetto *o*
- **create** subject *s'*: crea un nuovo soggetto
- **destroy** subject *s'*: elimina un soggetto
- **create** object *o'*: crea un nuovo oggetto
- **destroy** object *o'*: elimina un oggetto
L'esecuzione di un comando c(x1, ..., xk) su uno stato di sistema Q = (S, O, A) causa la transizione ad uno stato Q' tale che:

> Q = $Q_0$ ⊢ ${op}_∗^1$ $Q_1$ ⊢ ${op}_∗^2$ ... ⊢ ${op}_∗^n$ $Q_n$ = Q'

Dove:
- c: nome del comando
- x1,...,xk: parametri di input (soggetti/oggetti)
- op∗1 ... op∗n sono operazioni primitive in c
Se la parte condizionale del comando non è verificata, allora il comando non ha effetto e 

> Q = Q'

## 2 -Si richiede di descrivere le caratteristiche principali della politica per il controllo dell’accesso MAC (Mandatory Access Control)
Il controllo degli accessi di tipo mandatorio è uno delle 3 classi di politiche di sicurezza per il controllo degli accessi (DAC, MAC, RBAC). La politica mandatoria impone restrizioni sul flusso di informazioni e quindi a differenza delle politiche discrezionali non può essere soggetto ad attacchi come il Trojan Horse (si ricorda che le politiche discrezionali ne sono affette perchè controllano solo gli accessi diretti e non controllano quello che accade alle informazioni una volta rilasciate). Le politiche mandatorie introducono una distinzione tra users e subjects:
- **User**: essere umano
- **Subject**: un processo nel sistema (programma in esecuzione) che opera a nome dell'utente che lo ha lanciato
Mentre gli utenti possono essere attendibili per non comportarsi in modo improprio, i programmi che eseguono non lo sono. La forma più comune di politiche mandatorie sono quelle multilivello. In queste politiche si effettua la classificazione di soggetti ed oggetti e possono essere distinte in due classi:
- **Secrecy-based**: per la protezione della confidenzialità (modello Bell La Padula)
- **Integrity-based**: per la protezione della integrità (modello Biba)
Una classe di sicurezza è solitamente composta da due elementi:
- **Livello di sicurezza**: è un elemento di un insieme gerarchico di elementi (i.e. TS > S > C > U)
- **Categorie**: un insieme di elementi non gerarchici che possono rappresentare differenti aree di competenza all'interno del sistema
La combinazione di questi 2 elementi introduce un ordine parziale sulle classi di sicurezza denominato "**dominanza**":

> (L1, C1) domina (L2, C2) ⇐⇒ L1 ≥ L2 ∧ C1 ⊇ C2

Le classi di sicurezza insieme alla dominanza introducono un reticolo di classificazione:
- **Riflessività della dominanza**: ∀x ∈ SC : x domina x
- **Transitività della dominanza**: ∀x, y, z ∈ SC : x domina y, y domina z ⇒ x domina z
- **Antisimmetria della dominanza**: ∀x, y ∈ SC : x domina y, y domina x ⇒ x = y
- **Least upper bound (lub)**: ∀x, y ∈ SC : ∃ !z ∈ SC  
	- z domina x and z domina y  
	- ∀t ∈ SC : t domina x and t domina y ⇒ t domina z
- **Greatest lower bound (glb)**: ∀x, y ∈ SC : ∃ !z ∈ SC  
	- x domina z and y domina z  
	- ∀t ∈ SC : x domina t and y domina t ⇒ z domina t

Ad ogni utente è assegnata una classe di sicurezza (la sua clearance). Un utente può connettersi al sistema con qualsiasi classe dominata dalla sua clearance. I soggetti attivati in una sessione ereditano la classe di sicurezza con cui l'utente si è connesso al sistema. Una classe di sicurezza viene anche assegnata agli oggetti di modo da poter controllarne gli accessi sulla base dei permessi del soggetto

## 3 - Nell'ambito delle politiche di controllo dell’accesso DAC, si richiede di descrivere le principali debolezze di queste politiche (trojan horse)
Le politiche discrezionali (a differenza di quelle mandatorie) controllano solamente gli accessi "diretti". Non sono in grado di controllare i flussi di informazione e quindi non offrono controllo su quello che succede alle informazioni una volta che sono state rilasciate. Le politiche discrezionali sono quindi vulnerabili ad attacchi di tipo **Trojan Horse**, ossia software malevolo che contiene codice nascosto che sfrutta i privilegi di accesso del soggetto chiamante per compiere azioni malevole. Supponiamo di avere un soggetto **A** proprietario di un file e un soggetto **B** (malevolo) che desidera leggere il contenuto nascosto del file di **A**. Il soggetto **B** crea un file vuoto e concede al soggetto **A** le autorizzazioni di scrittura su questo nuovo file (operazione concessa, non c'è nulla che gli vieti di farlo). A questo punto supponiamo anche che esista una applicazione che è stata opportunamente modificata dal soggetto **B** e che tra le sue istruzioni legge il file del soggetto **A** e scrive il file vuoto di **B**. Se l'applicazione viene eseguita dal soggetto **A**, viene lanciata con i privilegi di **A**. Viene quindi letto il file di **A** e scritto il suo contenuto all'interno del file di **B** (il soggetto **A** ha i permessi di scrittura sul file di **B**). A questo punto il soggetto **B** è in grado di leggere il contenuto del file di **A** all'interno del proprio file e l'attacco si è concluso

## 4 - Nell'ambito delle politiche discrezionali, dire cosa rappresentano le ACL e le capability. Illustrare i vantaggi e gli svantaggi e fare un esempio
Le **ACL** e le **Capability Lists** sono degli approcci alternativi per l'implementazione del modello **Access Matrix**. Tale modello infatti presenta il problema di dover salvare una matrice che spesso è grande e sparsa. Questo implica ovviamente un inutile spreco di memoria. A tal proposito sono stati introdotti questi due approcci alternativi che consentono per l'appunto di risparmiare un po' di spazio in memoria a discapito di un po' di funzionalità:
- **ACL (Access Control Lists)**: è un approccio in cui per ogni oggetto del sistema si elencano i soggetti che hanno dei privilegi per quell'oggetto
- **Capability Lists**: è un approccio in cui per ogni soggetto del sistema si elencano gli oggetti su cui ha dei privilegi
Vi sono una serie di punti a favore delle ACL e un insieme di punti a favore delle Capability Lists:
- Le **ACL** richiedono l'autenticazione dei soggetti
- Le **Capability Lists** non richiedono l'autenticazione dei soggetti ma richiedono la non falsificabilità e il controllo della propagazione delle capabilities
- Le **ACL** sono superiori per il controllo degli accessi e la revoca basata sugli oggetti. Revoca basata sugli oggetti significa che se devo rimuovere un oggetto mi basta eliminare tutti i soggetti nella sua ACL. Se invece devo rimuovere un soggetto sono obbligato a scorrere tutte le ACL di tutti gli oggetti alla ricerca dei permessi di quel soggetto (da revocare)
- Le **Capability Lists** sono superiori per il controllo degli accessi e la revoca basata sui soggetti. Revoca basata sui soggetti significa che se devo rimuovere un soggetto mi basta eliminare tutti i permessi sui vari oggetti che sono contenuti nella capability list di quel soggetto. Se invece devo rimuovere un oggetto devo per forza scorrere tutte le capability lists di tutti i soggetti per eliminare tutti i permessi su quell'oggetto

Solitamente si utilizzano approcci basati sulle **ACL**
![[acl_capability.PNG]] 
A sinistra le **ACL** e a destra le **Capability Lists**

## 5 - Nell'ambito del modello relazionale multilivello, dire cosa si intende per tuple polinstanziate ed elementi polinstanziati e fornire un esempio
Oltre a modelli come Bell La Padula, presentati per introdurre politiche di sicurezza tipicamente nei sistemi operativi, sono stati studiati anche modelli multilivello da applicare ai DBMS. Siccome in un DBMS abbiamo le relazioni che al loro interno presentano istanze specifiche degli attributi di cui la relazione è composta, possiamo definire livelli di classificazione in maniera più fine rispetto a modelli come Bell La Padula. Posso per esempio decidere di applicare livelli di sicurezza a livello di relazione, di attributo, di tupla o addirittura a livello di cella. Un approccio a grana così fine deve però prendere in considerazione la semantica dei dati e la possibilità di avere perdite di informazioni. Si introduce quindi la **polinstanziazione**, ossia la presenza di più oggetti che hanno lo stesso nome ma differente classificazione. Abbiamo quindi tuple differenti con la stessa chiave ma:
- differente classificazione per la chiave (**tuple polinstanziate**)
- differenti valori e classificazioni per uno o più attributi (**elementi polinstanziati**)

![[polyinstantiation.PNG]]

## 6 -  Definire il concetto di politica aperta e politica chiusa. Per quale ragione può essere utile definire un sistema basato sia su autorizzazioni positive sia su autorizzazioni negative? Quali problemi possono sorgere a causa della presenza di autorizzazioni positive e negative?
Nell'ambito delle espansioni di autorizzazioni abbiamo visto come può essere utile definire sia autorizzazioni positive che autorizzazioni negative. Abbiamo dunque due tipologie di politiche:
- **Open policy**: quello che non è espressamente negato può essere eseguito
- **Closed policy**: possono essere eseguiti solo accessi esplicitamente concessi

Sono stati successivamente introdotti approcci ibridi che supportano entrambe le filosofie ma così facendo sono sorti due problemi:
- **inconsistenza**: ho un accesso che presenta sia autorizzazione positiva che negativa
- **incompletezza**: ho un accesso che non presenta nè autorizzazione positiva nè autorizzazione negativa

La incompletezza può essere risolta sia assumendo la completezza (per ogni accesso deve esistere almeno o una autorizzazione negativa o una positiva) oppure assumendo come decisione di base o la **Open policy** o la **Closed policy**. In generale sono state presentate molte politiche di risoluzione dei conflitti tra cui si ricordano:
- **denials-take-precedence**: le autorizzazioni negative vincono (principio di fail safe defaults di Saltzer e Schroeder)
- **most-specific-takes-precedence**: l'autorizzazione che è più specifica vince
- **most-specific-along-a-path-takes-precedence**: l'autorizzazione "più specifica" vince solo sui percorsi che la attraversano

Può essere utile definire un sistema in cui valgano sia autorizzazioni positive che autorizzazioni negative perchè altrimenti non potrei gestire in maniera efficiente eccezioni come la seguente: "tutti gli impiegati apparte Sam possono leggere un file". Con le autorizzazioni negative invece mi basta definire queste due autorizzazioni:
- **(Impiegati, read, file, +)**
- **(Sam, read, file, -)**

## 7 - Nell'ambito delle politiche basate sui ruoli, descrivere il principio di separazione dei privilegi (statico e dinamico) e fornire un esempio
Il principio di separazione dei doveri dice che nessun utente (o un insieme limitato di utenti) dovrebbe disporre di privilegi sufficienti per poter abusare del sistema. Può essere:
- **Statico**: chi specifica le autorizzazioni deve assicurarsi di non dare "troppi privilegi" ad un singolo utente
- **Dinamico**: il controllo per limitare i privilegi avviene a runtime. Nello specifico un utente non può usare "troppi" privilegi ma può scegliere quali usare. Il sistema conseguentemente negherà gli altri accessi (è più flessibile)

Esempio:
Ho un sistema su cui si possono compiere 4 operazioni (ordina_beni, invia_ordine, registra_ricevuta, paga). Ho 4 impiegati e il seguente requisito di protezione: "almeno 2 persone devono partecipare nel processo":
- **Statico**: l'amministratore assegna le operazioni agli impiegati di modo che nessuno possa eseguirle tutte e 4
- **Dinamico**: ogni utente può eseguire qualsiasi operazione purchè non completi da solo tutte e 4 le operazioni

## 8 - Nell'ambito della implementazione della selective encryption in OpenStack, cosa rappresenta la DEK di un oggetto e la KEK di un utente?
La **DEK** (Data Encryption Key) è una chiave simmetrica utilizzata per cifrare gli oggetti all'interno dei container. Una **KEK** (Key Encryption Key) è una chiave ottenuta cifrando una **DEK** (con la master key del cifrante) che un utente può estrarre usando una chiave segreta che solo l'utente conosce. Nello specifico:
- Ogni utente *u* crea tanti container quanti gliene servono. Ogni container è associato con una **DEK** univoca
- Tutti gli oggetti all'interno del container sono cifrati con la **DEK** corrispondente
- Ogni **DEK** è cifrata con la master key dell'utente *u* e la **KEK** risultante è salvata nel repository di *u*
- Per ogni container e per ogni utente *uj* nella ACL del container, *u* cifra la **DEK** con la chiave pubblica di *uj* (*puj*) e la firma usando la propria chiave privata *ssu*. La **KEK** risultante è salvata nel repository di *uj*

## 9 - Descrivere il concetto di polinstanziazione. Fare un esempio di tabella con tuple e con elemento polinstanziati
(POLINSTANZIAZIONE GIA' SPIEGATA ALLA DOMANDA 5 - AGGIUNGO SOLO COSE NON DETTE)
La polinstanziazione può essere di due tipi:
- **Invisibile**: un soggetto di basso livello chiede l'inserimento di una tupla ma la relazione contiene già una tupla che ha la stessa chiave primaria ma con una classificazione più alta. Ecco le possibilità da prendere in considerazione:
	- Dire al soggetto che non può fare l'inserimento -> Leakage di informazione perchè così il soggetto inferisce che esiste un'altra tupla con la stessa chiave ma di livello più alto
	- Sostituire la vecchia tupla con quella nuova -> Perdita di integrità perchè il soggetto di alto livello adesso vede cambiata la classificazione della tupla
	- Inserire la nuova tupla -> Crea una tupla polinstanziata
- **Visibile**: un soggetto di alto livello chiede l'inserimento di una nuova tupla ma la relazione contiene già una tupla con la stessa chiave primaria ma con una classificazione più bassa. Ecco le possibilità da prendere in considerazione:
	- Dire al soggetto che non può fare l'inserimento -> Denial Of Service perchè sto negando la possibilità di fare un inserimento ad un utente che a livello teorico è più fidato
	- Sostituire la vecchia tupla con quella nuova -> Leakage di informazione perchè il soggetto di basso livello si troverà con una tupla in meno e quindi inferisce che è stata inserita una nuova tupla con la stessa chiave primaria ma con livello più alto
	- Inserire la nuova tupla -> Crea una tupla polinstanziata

La polinstanziazione è una delle principali cause del non successo dei database multilivello ma non è sempre negativa. Può essere utile per sostenere le cover stories:
- **Cover story**: ritornare ad un soggetto di basso livello valori non corretti per proteggere l'informazione reale (utile per evitare il leakage di informazioni)

## 10 - Nell'ambito del problema della integrità del risultato di query, dire cosa si intende per completezza, correttezza e freschezza del risultato di una query. Si richiede inoltre di descrivere una tecnica deterministica di controllo dell’integrità
Siamo nell'ambito delle query collaborative, ossia quelle query in cui abbiamo differenti data owners che mettono a disposizione dei client i dati. Tuttavia i dati devono essere computati da un computational cloud che non è fidato e quindi può compiere le seguenti operazioni sul risultato che deve restituire al client richiedente:
- **Injection**: il computational cloud inserisce nel risultato anche informazioni fasulle
- **Drop**: il computational cloud omette alcune informazioni nel risultato (magari per risparmiare qualche periodo di computazione)
- **Omission**: il computational cloud esegue la query su una versione obsoleta dei dati e quindi il risultato non è più attendibile

I proprietari dei dati e gli utenti richiedono le seguenti proprietà per soddisfare l'integrità dei risultati delle query:
- **Correttezza**: la computazione è fatta su dati genuini (per combattere la injection)
- **Completezza**: la computazione è fatta sull'intera collezione di dati (per combattere il drop)
- **Freschezza**: la computazione è fatta sulla versione più recente dei dati (per combattere l'omission)

Una tecnica deterministica per il controllo dell'integrità è per esempio la tecnica **Signature-based**:
- Le tuple nel database vengono ordinate in accordo al valore di un attributo A
- Coppie consecutive di tuple vengono firmate insieme:

> ($t_1$, $s_1$); ($t_2$, $s_2$); . . . , ($t_m$, $s_m$); $t_x$ with $s_i$ = φ ($t_i$ | $t_{i+1}$)

Per velocizzare l'esecuzione delle query lato server, si può costruire un **B+-tree** sull'attributo *A*:
- L'esecuzione e la verifica della query segue questo processo:
	- Vengono restituite le tuple nel range [a-1, b+1] insieme alle firme in [a-1, b] (il risultato della query include tutte le tuple in [a, b])
	- Si verificano coppie consecutive di tuple. Qualora una verifica dovesse fallire allora vuol dire che il risultato non è integro

## 11 - Nell'ambito delle tecniche per la verifica della integrità del risultato di query, si richiede di descrivere le differenze principali tra le tecniche deterministiche e le tecniche probabilistiche. Si richiede inoltre di fare un esempio di tecnica probabilistica e del suo funzionamento
Nell'ambito dell'integrità delle query si possono distinguere due tipologie di approcci per garantire correttezza, completezza, freschezza delle query:
- **Deterministico**: utilizza strutture dati autenticate (i.e. catene di firme, Merkle hash trees, skip lists) oppure soluzioni che sfruttano la crittografia (i.e. verifiable homomorphic encryption schema)
- **Probabilistico**: sfrutta l'inserimento di tuple fake nei risultati delle query, replicazione di tuple nei risultati delle query e gettoni pre computati
	 
Utilizzando un approccio deterministico ho la certezza che il risultato sia integro ma ho delle limitazioni sulle query che posso eseguire a causa del funzionamento delle strutture autenticate che utilizzo. Utilizzando invece un approccio probabilistico c'è una certa probabilità *P* che il risultato della query sia integro. Per alzare la probabilità *P* devo aumentare il numero di meccanismi che utilizzo per proteggere l'integrità ma questo causa sicuramente un rallentamento generale durante la computazione dei risultati (aggiungo molto overhead, soprattutto con salts e buckets). Un esempio di tecnica probabilistica è l'inserimento di **tuple fake** nel database per poi andare a verificare se le si ritrova all'interno del risultato della query computata. Le tuple fake possono essere generate con due approcci:
- **Randomized approach**: le tuple fake sono generate in maniera randomica e sono salvate lato client. Quando il client ottiene il risultato RQ per la query Q dal server, esegue la query Q anche sulla propria copia di tuple fake per determinare quali tuple fake dovrebbero apparire in RQ
- **Deterministic approach**: le tuple fake sono generate attraverso una funzione deterministica definita come segue:

   > F : $D_1$ × . . . × $D_{n−1}$ → $D_n$
   
   Con $D_i$ il dominio dell'i-esimo attributo. I domini degli attributi sono divisi in griglie "discretizzando" ogni attributo (se l'attributo è numerico). Il risultato della query può essere visto come un set di griglie parzialmente e totalmente coperte. La completezza della query è poi verifica contando quante tuple fake contengono le varie griglie totalmente o parzialmente coperte. Contare il numero di tuple fake all'interno di una griglia totalmente coperta è facile; il numero può essere salvato direttamente insieme alla griglia. Per contare il numero di tuple fake all'interno di una griglia parzialmente coperta invece occorre che la funzione di generazione utilizzata sia crescente di modo che prendendo due punti di intersezione della funzione con la griglia sia facile contare le tuple che ricadono nel range tra i due punti

## 12 - Nell'ambito di query distribuite, quando due autorizzazioni definite come coppie [Attributi,Relazioni] possono essere combinate in modo safe? Si richiede di fornire un esempio
Due permessi $p_i$ e $p_j$ definiti come coppie $p_i$=[${Attr}_i$, ${Rel}_i$] e $p_j$=[${Attr}_j$, ${Rel}_j$] possono essere composti in maniera sicura se e solo se la loro composizione non aggiunge informazioni:
- **$p_i$ -> $p_j$** : $p_j$ dipende da $p_i$ se e solo se esiste un percorso che va dai nodi corrispondenti all'intersezione tra ${Attr}_i$ e ${Attr}_j$ a tutti i nodi neri nel grafo $G_{p_j}$ (Significa che $p_j$ dipende da $p_i$)
- Due permessi $p_i$ e $p_j$ possono essere **composti in maniera sicura** se e solo se vale almeno una di queste due dipendenze **$p_i$ -> $p_j$ o $p_j$ -> $p_i$**
- La composizione del permesso ha questa forma: **$p_i$ ⊗ $p_j$ = [${Attr}_i$ ∪ ${Attr}_j$, ${Rel}_i$ ∪ ${Rel}_j$]**

![[safe_composition.PNG]]

## 13 - Nell'ambito delle tecniche per la specifica di requisiti utenti per la scelta di cloud provider, perchè è importante anche supportare, oltre che la specifica dei requisiti, anche la specifica di preferenze? Ad esempio, quali tipi di preferenze possono essere specificate?
Nell'ambito delle tecniche per la specifica di requisiti utenti per la scelta di cloud provider è importante anche supportare, oltre che la specifica dei requisiti, anche la specifica di preferenze perchè una volta ottenuta la lista dei piani accettabili è necessario effettuarne il ranking. Un piano *P* è modellato come un insieme [$a_1$, ..., $a_n$] di attributi di interesse (i.e. Nome del provider, posizione dei server, algoritmi di cifratura utilizzati, disponibilità, autorità di pentesting, certificazioni di sicurezza, frequenza di audit...). I requisiti restringono i valori che possono essere assunti da un piano. I requisiti vengono specificati attraverso un linguaggio espressivo e user-friendly. Dati i seguenti piani:
![[plans.PNG]]e i requisiti $c_1$, ..., $c_5$, un piano **è accettabile** se e solo se soddisfa tutti i requisiti. Quindi $P_2$, $P_3$, $P_4$ e $P_5$ sono accettabili mentre $P_1$ non è accettabile. Le preferenze possono essere di due tipi:
- **Sui valori degli attributi**: alcuni valori sono preferibili ad altri per un attributo. Questo viene modellato attraverso una relazione di preferenza:
	- **Relazione di ordine totale su un set di valori accettabili**: per esempio prov: {MHard} > {GoGo} > {Ghost}
	- **Funzione di punteggio che riflette la posizione relativa dei valori**: per esempio MHard (3/3 = 1) - GoGo (2/3) - Ghost (1/3) 
	Viene quindi calcolato uno scoring vector $Π_i$ che include i punteggi dei valori di $P_i$:
	![[scoring_vector.PNG]]

- **Sugli attributi stessi**: certi attributi sono più importanti di altri. Questo viene modellato attraverso una funzione pesata:
	- **Peso maggiore implica importanza maggiore**: w(prov) = 1, w(avail) = 10 -> avail è più importante

## 14 - Nell'ambito dei modelli per la specifica di autorizzazioni basati su tre livellli di visibilità (plaintext, encrypted e no visibile), cosa cattura il profilo di una relazione? Quale è il profilo di una relazione R ottenuta tramite il prodotto cartesiano di due relazioni R1 e R1?
Nell’ambito dei modelli per la specifica di autorizzazioni basati su tre livellli di visibilità (**plaintext**, **encrypted** e **non visibile**), il profilo della relazione cattura il contenuto informativo di una relazione **R** e include:
- **v**: gli attributi visibili: cifrati o in chiaro nello schema di R
- **i**: gli attributi impliciti: convogliati cifrati o in chiaro da R
	- **selezione**: SELECT S FROM Hosp WHERE D='stroke'
	fa leakage del valore di D, anche se D non appartiene allo schema
	- **raggruppamento**: SELECT COUNT(*) FROM Hosp JOIN Ins ON S=C GROUP BY T
	fa leakage di informazioni sulle tuple che hanno lo stesso valore di T, anche se T non appartiene allo schema
- **≃**: relazione di equivalenza: fra gli attributi connessi nella computazione di R
		 - confrontando gli attributi: SELECT S FROM Hosp JOIN Ins ON S=C
		    fa leakage dei valori di C, anche se C non appartiene allo schema

Dati $R_l$ = [v : {$R_l^{vp}$, $R_l^{ve}$}, i : {$R_l^{ip}$, $R_l^{ie}$}, ≃ : {$R_l^{≃}$}] e $R_r$ = [v : {$R_r^{vp}$, $R_r^{ve}$}, i : {$R_r^{ip}$, $R_r^{ie}$}, ≃ : {$R_r^{≃}$}]
Il prodotto cartesiano × delle relazioni corrisponde alla relazione:
- **v** : {$R_l^{vp}$ ∪ $R_r^{vp}$ ∪ $R_l^{ve}$ ∪ $R_r^{ve}$}
- **i** : {$R_l^{ip}$ ∪ $R_r^{ip}$ ∪ $R_l^{ie}$ ∪ $R_r^{ie}$}
- **≃** : {$R_l^{≃}$ ∪ $R_r^{≃}$}

## 15 - Nell'ambito delle tecniche per l’esecuzione selettiva di query distribuite, dire cosa rappresenta il profilo di una relazione R definito come [Rπ , Rσ , R⋈]. Fornire inoltre un esempio di interrogazione con il relativo profilo della relazione risultante
Nell'ambito delle tecniche per l'esecuzione selettiva di query distribuite, il profilo [$R^π$, $R^⋈$, $R^σ$] rappresenta:
- $R^π$: **Schema di R** (il contenuto informativo, ossia gli attributi)
- $R^⋈$: **Join path** (possibilmente vuoto) usato nella definizione di R
- $R^σ$: **Set di attributi** (possibilmente vuoto) coinvolti in una condizione di selezione di R (gli attributi nella clausola WHERE)

Esempio:
**SELECT** illness
**FROM** Disease **JOIN** Hospital **ON** illness=disease
**WHERE** treatment='antistaminico'
Profilo:  [$R^π$, $R^⋈$, $R^σ$] = [(illness),(<D.illness, H.disease>), (treatment)]

## 16 - Nell'ambito dei modelli di autorizzazione per query distribuite che supportano la specifica del join path, dire cosa rappresenta il profilo di una relazione [Rπ ,  R⋈, Rσ] e fare un esempio di select-where query con associato il profilo relativo al risultato della query
GIA' RISPOSTA NELLA DOMANDA 15

## 17 - Nell'ambito di query distribuite, dire in che cosa consiste la tecnica per l’esecuzione di join detta sovereign join
L'accesso ai dati e l'esecuzione di query è molto più complesso negli scenari emergenti:
- I dati possono essere salati al di fuori del controllo del proprietario
- L'esecuzione di applicazioni/query può comportare l'accesso ai dati da parte di attori differenti
- I dati possono essere spostati in diverse locations

Occorre quindi definire e specificare delle costanti per il data sharing che consentano di regolare l'esecuzione di query in ambienti distribuiti con differenti attori. La tecnica dei **sovereign joins** consente di computare join in modo tale che nulla al di fuori del risultato del join sia rivelato. Ecco un possibile scenario di utilizzo:
- I proprietari delle 2 relazioni non si fidano l'un l'altro, nessuno dei due dovrebbe vedere la relazione dell'altro o il risultato della query
- L'attore che richiede la query è differentie rispetto a questi due proprietari
- Il server che esegue la query non è fidato dal punto di vista della confidenzialità
- Il server è equipaggiato con un processore sicuro e anti manomissione che è autorizzato a vedere il contenuto delle due relazioni

Esecuzione della query:
- Il client manda l'operazione di join al server
- Il server ha la versione cifrata delle relazioni originali
- Il server invia la query e le relazioni cifrate al processore
- Il processore decifra le relazioni ed esegue il join
- Il processore cifra il risultato del join con una chiave condivisa con il client e restituisce il risultato cifrato al server
- Il server invia il risultato cifrato al client

Tutto questo comporta un elevatissimo costo computazionale e vi è la necessità di possedere un componente fidato (il processore). L'operazione di join deve essere eseguita con cautela siccome il processore ha risorse e memoria limitate. Qualsiasi osservazione sull'interazione tra il processore e il server non deve rivelare alcuna informazione sul risultato del join o sugli operandi. Le operazioni di join devono soddisfare due proprietà:
- **Fixed time**: il tempo per la valutazione della condizione di join e per la composizione delle tuple è lo stesso indipendentemente dal risultato
- **Fixed size**: la dimensione del risultato ottenuto comparando le tuple è la stessa indipendentemente dal risultato

## 18 - Nell'ambito della differential privacy, cosa si intende per composizione sequenziale e composizione parallela? Fornire un esempio
La differential privacy si compone bene con se stessa:
- **Composizione sequenziale**: si tratta di una sequenza di *m* computazioni sullo stesso dataset **D** dove ε = $ε_1$ + $ε_2$ + ... + $ε_m$ può essere interpretata come segue: se fissiamo un valore di **ε** "limite" possiamo dire che più computazioni faccio (con valori sovrapposti) più aumenta il rischio questo valore limite sia superato e che quindi la privacy venga violata. La composizione sequenziale implica quindi che possiamo (per esempio) fare una sola computazione con ε = 1 oppure 10 computazioni con ε = 0.1 e ottenere lo stesso grado di protezione
- **Composizione parallela**: si tratta di una sequenza di *m* computazioni su subset disgiunti del dataset **D** dove ε = max($ε_1$, $ε_2$, ..., $ε_m$)

**Esempio di composizione sequenziale**: chiedere il conteggio di pazienti femmina e il conteggio di pazienti che soffrono di diabete in un ospedale: (numero di femmine = 34 e numero di persone con diabete = 23). Le celle del risultato possono essere intersecate (ci sono femmine che soffrono di diabete). Ogni conteggio deve quindi essere rilasciato in modo tale che $ε_1$ (dal conteggio delle femmine) + $ε_2$ (dal conteggio delle persone con il diabete) sia uguale a ε. Questo significa che la somma è al più ε, altrimenti non rispetto il requisito di privacy che ho fissato a priori

**Esempio di composizione parallela**: chiedere il conteggio delle persone divise tra mancini, destrorsi e colore dei capelli. Ogni cella è un insieme disgiunto di individui (se sono biondo posso essere o mancino o destrorso; idem se sono rosso o se sono castano). Ogni cella può essere rilasciata con ε-differential privacy. Tuttavia ε >= max($ε_1$, $ε_2$, ..., $ε_m$) altrimenti di nuovo rischio di perdere privacy

## 19 - Quale è la differenza tra global differential privacy e local differential privacy?
Sia la **global differential privacy** che la **local differential privacy** sono modelli per implementare la differential privacy. La **global differential privacy** si applica su tutto il dataset (compresi gli input). Quindi ho una parte fidata che riceve i dati dagli utenti ed effettua la computazione in contemporanea all'aggiunta del rumore (la parte fidata ha quindi accesso ai dati originali). La **local differential privacy** invece si applica individualmente ad ogni input prima di popolare il dataset (è l'utente stesso che prima di rilasciare i dati li maschera). La parte che effettua la computazione dei dati infatti non è fidata. La quantità di rumore introdotto con questo tipo di differential privacy è tipicamente maggiore rispetto a quella global perchè con questa tecnica il rumore applicato sui singoli elementi può essere cancellato o sottratto. Un algoritmo A soddisfa la ε-differential privacy se e solo se per tutti gli input x, x' e per tutti gli output o di A: P[A(x) = o] <= $e^ε$ P[A(x') = o], cioè ogni output non dovrebbe dipendere dai segreti dell'utente

## 20 - Cosa vuol dire che differential privacy è “chiusa rispetto a operazioni di post-processing”?
Significa che se applico operazioni di post-processing ai dati dopo aver applicato la differential privacy non cambiano le garanzie di privacy che ho. Spesso è necessario applicare operazioni di post-processing per rendere "realistici" dati che magari sono stati generati con un rumore che non è sensato nel contesto di riferimento: per esempio posso avere una situazione in cui un valore di età, dopo aver eseguito un algoritmo di differential privacy, è negativo (cosa non realistica) e quindi devo renderlo quanto meno >= 0

## 21 - Nell'ambito della differential privacy, si richiede di fornire la definizione formale di algoritmo che soddisfa la definizione di ε-differential privacy. Si richiede inoltre di descrivere, fornendo anche un esempio, cosa si intende per global sensitivity e a cosa serve
Un algoritmo **A** soddisfa la **ε-differential privacy** se per ogni coppia di database vicini **D** e **D'** e per tutti gli output *o*:

> P[A(D) = o] <= $e^ε$ P[A(D') = o]

Significa che un potenziale attaccante non dovrebbe essere capace di usare l'output *o* per distinguere tra **D** e **D'**. Per far funzionare bene la differential privacy occorre che il dataset **D** sia "grande".
- **ε piccolo** -> + privacy, - utilità
- **ε grande** -> - privacy, + utilità

La **global sensitivity** è un meccanismo che consente di calibrare il rumore sulla base dell'influenza che un individuo può avere sul risultato (nel caso peggiore). 
**Esempio**:
Quante persone soffrono di diabete? Supponiamo che nel database con un totale di 70 persone io abbia 50 persone che soffrono di diabete; se dovessi rimuovere dal dataset una persona che il diabete non ce l'ha, questa avrebbe influenza 0 (non cambia il numero di persone che hanno il diabete tra il dataset originale e quello con la differential privacy applicata). Se invece tolgo un individuo che soffre di diabete allora nel dataset "elaborato" ho 49 persone con il diabete anzichè 50. Posso quindi dire che la sensitività globale è **GS(A)** = 50 - 49 = 1

## 22 - Nell'ambito delle blockchain, si richiede di descrivere (ad alto livello) come funziona il protocollo del consenso
L'algoritmo del **consenso** nell'ambito delle blockchain funziona nel seguente modo:
- Le transazioni vengono inviate in broadcast a tutti i nodi
- Ogni nodo colleziona le transazioni in un blocco
- Ad ogni round, un nodo random può condividere il suo blocco. In realtà non è proprio random ma suppongo che la selezione del nodo venga fatta in proporzione alle risorse computazionali dei nodi stessi (**proof-of-work**). Quindi il nodo che viene selezionato è un nodo che ha:
	- Verificato che tutte le transazioni siano valide
	- Calcolato per primo un nonce valido (**hash puzzle**). Il nonce andrà inserito all'interno dello header del blocco. Si tratta della computazione più complessa da fare
- Gli altri nodi accettano il blocco solo se tutte le transazioni al suo interno sono valide
- I nodi esprimono l'accettazione del blocco in maniera implicita includendo il suo hash all'interno del blocco successivo che creano (lo rifiutano invece includendo l'hash del blocco precedente all'interno del successivo che creano)

## 23 - Nell'ambito delle blockchain, in cosa consiste la tecnica detta proof-of-work ? A cosa serve?
La tecnica del **proof-of-work**, assieme al sistema del block reward fa parte del sistema di incentivi per evitare che i nodi creino blocchi malevoli. La **proof-of-work** è un sistema che serve a verificare che un determinato nodo abbia speso un quantitativo di lavoro (risorse di calcolo) per generare il blocco che ha presentato in broadcast. Questo viene effettuato tramite il **target space** e il calcolo del **nonce**, cioè bisogna trovare un nonce tale che l'hash **H(nonce || prev_hash || $t_x$ || ... || $t_x$)** sia abbastanza piccolo da essere in un determinato range di valori detto "target space". Se la funzione di hash è sicura, l'unico modo per trovare il nonce è testarne tanti fino che non se ne trova uno valido. I vantaggi di questa tecnica sono diversi:
- **Difficile da computare**: circa $10^{20}$ hashes/block
- **Il costo è parametrizzabile**, il target space può essere modificato in modo che in media si generi un blocco ogni 10 minuti
- **Facile da verificare**: ogni nodo che deve verificare la correttezza della **proof-of-work** basta che verifichi che l'hash del blocco sia minore del target space

## 24 - Nell'ambito delle blockchain, si richiede di descrivere la struttura di un blocco
La struttura di un blocco della blockchain è divisa in due sezioni:
- **Header**: che contiene le informazioni sul blocco:
	- Versione
	- Hash del blocco precedente (computato sullo header attraverso l'algoritmo SHA256). Permette di creare una catena di blocchi (la blockchain) e quindi un registro digitale immutabile
	- Timestamp
	- Radice di un albero di Merkle (l'hash della radice dell'albero di Merkle delle transazioni del blocco)
	- Target di difficoltà (il target definito dall'algoritmo di proof-of-work per il blocco)
	- Nonce (il numero utilizzato per risolvere l'hash puzzle nell'algoritmo di proof-of-work)
- **Lista delle transazioni**

## 25 - Da dove deriva il nome di "politiche discrezionali"? Come è definito lo stato del sistema nel modello a matrice di accesso?
Il nome "politiche discrezionali" deriva dal fatto che è a discrezione del proprietario di una risorsa decidere i privliegi e a chi assegnarli o revocarli. Il garantire/revocare i permessi è regolato da una politica amministrativa. IL RESTO E' GIA' STATO RISPOSTO NELLA DOMANDA 1

## 26 - Nell'ambito del modello Chinese Wall si richiede di enunciare la simple security rule e di mostrare un esempio di accesso che viene concesso
Il modello **Chinese Wall** è uno speciale modello di tipo mandatorio ma con **separazione dinamica dei doveri** per la protezione della segretezza. Il goal di questo modello è quello di prevenire flussi di informazioni che possano cause un conflitto di interessi per consulenti di società differenti (un consulente non dovrebbe essere a conoscenza di dati di dati di 2 banche o 2 compagnie petrolifere). Gli oggetti in questo modello sono organizzati gerarchicamente. Ci sono 3 livelli:
- **Basic objects**: per esempio i file
- **Company datasets**: gruppi di oggetti che fanno riferimento alla stessa organizzazione
- **Conflict of interest classes**: gruppi di company datasets che sono in competizione tra di loro

**Premessa**: all'inizio tutti possono fare quello che vogliono (**nessuna restrizione**). Man mano che tu accedi alle risorse si restringe quello che puoi fare sul sistema. Questo è il tipico esempio di **dynamic separation of duties**. 
- **Simple security rule**: un soggetto *s* può leggere un oggetto *o* solo se (deve valere una delle due):
	- *o* è nello stesso company dataset di tutti gli oggetti che *s* ha già acceduto
	- *o* si trova in un conflitto di interessi totalmente differente

Gli utenti possono avere la necessità di comparare le informazioni tra differenti aziende, quindi la simple security rule può essere **troppo stringente**. Questo modello prevede quindi che le informazioni possano essere sanificate (mascherandole) per prevenire l'identificazione dell'azienda. La simple security rule previene flussi di informazioni da un singolo utente. 

**Un esempio di accesso concesso è il seguente**:
Il soggetto **S** ha letto gli oggetti $O_1$, $O_2$ ed $O_3$ che appartengono al company dataset **A**. **S** vuole leggere l'oggetto $O_4$. Se $O_4$ appartiene al company dataset **A** allora l'oggetto può essere letto. Se si trova in un company dataset differente ma nella stessa classe di conflitto di interesse allora non può leggerlo. L'oggetto $O_4$ può anche essere letto se appartiene ad una classe di conflitto di interesse diversa da quella degli oggetti $O_1$, $O_2$ e $O_3$

## 27 - Nell'ambito delle tecniche per la verifica della integrità del risultato di interrogazioni, cosa si intende per correttezza, completezza e freschezza del risultato? DIre inoltre a cosa serve il Merkle hash tree ed illustrare un esempio di verifica (l'albero di esempio può essere descritto testualmente per livelli, partendo dal nodo radice e andando verso le foglie)
PRIMA PARTE GIA' RISPOSTA NELLA DOMANDA 10. Il **Merkle hash tree** è una tecnica deterministica per verificare l'integrità delle query. Si tratta di un albero binario dove:
- ogni foglia contiene l'hash di una tupla
- ogni nodo interno contiene il risultato dell'hash della concatenazione dei suoi figli

La funzione di hash utilizzata per costruire l'albero è **resistente alle collisioni**. La radice è firmata dal proprietario dei dati e la firma viene inviata agli utenti autorizzati. Le tuple nelle foglie sono ordinate secondo il valore dell'attributo **A** su cui l'albero è definito. L'albero è creato dal proprietario dei dati e salvato sul server. 

**Esempio**:
Nelle foglie abbiamo gli hash delle tuple ordinate secondo un attributo (su cui l'albero è costruito): $h_1$ = h($t_1$) - $h_2$ = h($t_2$) - $h_3$ = h($t_3$) - $h_4$ = h($t_4$)...
Al livello successivo troviamo gli hash concatenati delle foglie: $h_{12}$ = h($h_1$ || $h_2$) - $h_{34} = h($h_3$ || $h_4$)
Nella radice: $h_{1234}$ = h($h_{12}$ || $h_{34}$)
**L'albero di Merkle** definito su **A** supporta la verifica di query di eguaglianza e di range su **A**. Il server, oltre al risultato della query, restituisce un **verification object** (l'hash delle altre tuple necessarie per derivare l'hash della radice). Il client usa il verification object e il risultato della query per ricostruire l'hash della radice dell'albero. Il risultato della query è corretto e completo se e solo se la radice computata è la stessa di quella che conosce. Se manca una tupla o se non è corretta sicuramente l'hash della radice ricomputato sarà diverso da quello conosciuto. Nell'esempio di prima, supponendo di voler trovare la tupla $t_3$, avrò un verification object composto dall'hash $h_4$ e dall'hash $h_{12}$. Sarò così in grado di ricomputare la radice dell'albero per verificare se la query è integra

## 28 - Nell'ambito di interrogazioni distribuite, in cosa consiste la tecnica basata sul concetto di access pattern? Mostrare un esempio di interrogazione e come può essere eseguita in base a tale tecnica
La tecnica degli **access patterns** consente di specificare limitazioni su come vengono accedute le fonti di informazione. Ogni attributo di una vista/relazione ha un valore di input o di output e le relazioni possono essere accedute solo in accordo al corrispondente access pattern. 

**Esempio**:
$Insurance^{oi}$(holder, plan)
$Hospital^{oioo}$(patient, YoB, disease, physician)
$Nat_registry^{ioo}$(citizen, YoB, healthid)

**Query**:
**SELECT** patient
**FROM** Insurance **JOIN** Hospital **ON** holder = patient
**WHERE** plan = "annual"
      
La query non può essere soddisfatta nella maniera tradizionale perchè l'attributo YoB di Hospital non è specificato e quindi non è consentito l'accesso a patient in output perchè non è stato ricevuto in input uno YoB. Occorre quindi accedere ad Insurance per ricavare holder (inserendo in input plan per avere come output holder). Si esegue il join tra Insurance e Nat_registry (citizen viene fornito in input tramite il join con holder e quindi ho successivamente accesso agli attributi YoB e healthaid di Nat_registry). Ho quindi ottenuto l'accesso a YoB che mi consente "sbloccare" patient della tabella Hospital

## 29 - Nell'ambito di interrogazioni distribuite, quale è la differenza tra l'approccio sintattico e l'approccio semantico dei modelli che regolano la condivisione selettiva di informazioni durante l'esecuzione di interrogazioni?
Nell'ambito di interrogazioni distribuite, la differenza tra l'approccio sintattico e l'approccio semantico è la seguente:
- **Syntactic**: il soggetto **S** è autorizzato a vedere una relazione **R** se e solo se ∃ [Attributes, Join Path] -> **S**: $R^π$∪$R^σ$⊆ Attributes e $R^{⊲⊳}$=Join Path. Si tratta di un approccio più semplice ma limitato dalla specifica delle autorizzazioni
- **Semantic**: il soggetto **S** è autorizzato a vedere una relazione **R** se e solo se **S** ha i permessi per vedere il contenuto informativo trasportato dalla relazione. Una query dovrebbe essere autorizzata se l'insieme dei permessi disponibili al soggetto potrebbe consentire al soggetto di computare il risultato della query in maniera indipendente

## 30 - Nell'ambito delle tecniche per la specifica di preferenze utente per la scelta di cloud plan, descrivere i requisiti soft di preferenza (valori attributi e attributi) e fornire degli esempi
GIA' RISPOSTA NELLA DOMANDA 13

## 31 - Nell'ambito della tecnica di differential privacy, cosa vuol dire che la differential privacy si compone bene con se stessa? Descrivere le composizioni e fare degli esempi
GIA' RISPOSTA NELLA DOMANDA 18

## 32 - Nell'ambito delle blockchain, cosa è l'hash puzzle?
Si tratta di un problema che i nodi devono risolvere per avere la possibilità di inserire il blocco che hanno computato all'interno della blockchain. Viene utilizzato nell'ambito del **proof-of-work** per fare in modo che un nodo che abbia grande potenza computazionale possa essere in grado di risolvere questo problema per primo. Fissato un target **T**, ossia un range in uno spazio di hash, i nodi devono trovare un numero **N** (nonce) tale che l'hash H(nonce || prev_hash || $t_x$ || ... || $t_x$) sia <= **T**. Il primo nodo che trova questo valore per il nonce ha la possibilità di inserire il suo blocco nella blockchain (il blocco deve anche contenere transazioni valide). L'unico modo che un nodo ha di trovare questo nonce è di calcolarne moltissimi finchè non ne trova uno valido (per questo motivo un nodo che ha più potenza computazionale ha più probabilità di trovare il nonce per primo)

## 33 - Nell'ambito delle tecniche probabilistiche per l'integrità delle computazioni, si richiede di descrivere cosa sono i twin, marker e quali sono le loro caratteristiche principali. Fare un esempio di tabella con twin e marker
I **markers** sono tuple artificiali iniettate in $R_l$ da $S_l$ e in $R_r$ da $S_r$ che il server che effettua le computazioni non deve riconoscere. Le tuple vengono inserite in una maniera tale da garantire che appartengano al risultato dei join. L'assenza dei markers all'interno del risultato di un join è un segnale di **incompletezza**. I **twin** invece sono tuple duplicate che soddisfano una condizione $C_{twin}$ che:
- è definita sull'attributo di join I
- aggiusta la percentuale $p_t$ di twins
- è definita dal client e comunicata a $S_l$ e $S_r$

Le coppie di twins non sono riconoscibili dal computational server. Se un twin appare da solo nel risultato di un join è segnale di **incompletezza**. Esempio di tabella con twins e markers:
I | Attr
------------ | ------------
a | Ann
b | Beth
c | Cloe
b_twin | Beth
x | marker1

## 34 - Nell'ambito delle tecniche per l'esecuzione selettiva di query distribuite, cosa si intende per Truman model e non-Truman model?
Siamo nell'ambito delle **view-based authorizations** che forniscono controllo degli accessi a grana fine dipendente dal contenuto nei database relazionali. Permette di scrivere le query in una maniera "authorization-transparent" secondo due approcci:
- Modifica delle query per rispondere alle query (**Truman model**)
- Un query è valida se può essere soddisfatta usando informazioni nelle authorization views disponibili allo user che la richiede (**non-Truman model**)

Se esiste una query scritta solo usando le authorized views istanziale dello user richiedente che è equivalente alla query originale, allora la query è accettata (**non-Truman**)

## 35 - Nell'ambito del modello di autorizzazione per query multi-provider, cosa rappresentano le tre componenti (visibile, implicito, equivalenze) del profilo di una relazione? Fare un esempio di query e specificare il relativo profilo
GIA' RISPOSTO NELLA DOMANDA 14

## 36 - Nell'ambito della differential privacy, che relazione c'è tra il fattore di scale λ del meccanismo di Laplace ed ε? Si richiede di spiegare cosa rappresenta λ
Il meccanismo di **Laplace** è una tecnica per generare rumore dove il risultato **R** è un campione estratto dalla distribuzione di **Laplace** che ha come media il risultato vero e una certa scala **λ** (determinata da **ε** e dalla **global sensitivity** della computazione): 

> R = A(D) + Z

con **Z** una variabile random estratta dalla distribuzione di **Laplace**. Più è piccolo il valore di lambda e più grande è la probabilità di generare poco rumore (e viceversa)

## 37 - Nell'ambito delle tecniche per la specifica di preferenze fuzzy, cosa sono i parametri fuzzy ed i concetti fuzzy? Si richiede di fare un esempio per ognuno di essi
NON SO ANCORA RISPONDERE

## 38 - Nell'ambito della differential privacy, dire come funziona (ad alto livello) Rappor
**Rappor** è usato per raccogliere informazioni statistiche sull'utilizzo delle applicazioni da parte degli utenti. Ogni utente ha un valore *v* estratto da un grande insieme di possibilità (per esempio un URL: www.unimi.it) che deve essere comunicato per motivi diagnostici. **Rappor** sfrutta un **Bloom Filter** e 2 livelli di risposte random (**permanente** ed **istantanea**). In una prima fase si utilizzano *h* funzioni di hash per effettuare l'hash della stringa in input (l'URL) su un vettore di k-bit (**Bloom filter**). Nella seconda fase si genera la "**permanent randomized response**": viene costruito un secondo **Bloom Filter** prendendo in input quello precedentemente generato e si modificano alcuni dei bit al sui interno utilizzando un parametro di probabilità *f*:
- si mette 1, con probabilità 1/2 *f*
- si mette 0, con probabilità 1/2 *f*
- si mette $B_i$ (il valore alla i-esima posizione del primo **Bloom Filter**), con probabilità 1 - *f*

**Permanent** perchè non viene modificato se decido di reinviare lo stesso URL. Nell'ultima fase si genera la "**instantaneous randomized response**": ogni volta che bisogna re-inviare la stessa stringa si ricalcola questo livello facendo un flip dei bit a 1 con probabilità 1 - *q* e facendo un flip dei bit a 0 con probabilità *p*

## 39 - Nell'ambito delle blockchain, cosa sono il block reward e transaction fee?
Per fare in modo che i nodi si comportino bene sono stati introdotti i cosiddetti "**incentivi**":
- **Block reward**: il creatore del blocco può:
	- includere una speciale transazione di creazione di monete nel blocco
	- scegliere l'indirizzo del destinatario di questa transazione
	- il valore è fissato e viene dimezzato ogni 4 anni
	-> il creatore del blocco riceve la ricompensa solo se il blocco finisce nel ramo del consenso più lungo
- **Transaction fee**: il creatore di una transazione può scegliere di rendere il valore di output inferiore al valore di input, introducendo così una sorta di commissione sulla transazione che va al creatore del blocco

## 40 - Descrivere la politica low-watermark per oggetti e fare un esempio di operazione di lettura che non può essere portata a termine e un esempio di operazione di scrittura
Siamo nell'ambito di uno dei rilassamenti concessi dal modello **Biba**, un modello **MAC** per proteggere l'integrità. Nello specifico la politica "**Low-watermark for objects**" consente di non avere vincoli in scrittura:
- Un soggetto **S** può leggere un oggetto **O** solo se la classe di **O** domina la classe di **S**
- Un soggetto **S** può scrivere qualsiasi oggetto **O**
- Dopo una scrittura la classe dell'oggetto **O** diventa il **glb** tra la classe del soggetto **S** e la classe dell'oggetto **O**

**Esempio di lettura non concessa**: il soggetto **S** ha una classe **TS** (top secret) mentre l'oggetto **O** ha una classe di sicurezza **C** (confidential)

**Esempio di scrittura**: è sempre concessa, qualsiasi siano le classi di sicurezza di **O** e di **S**

## 41 - Nell'ambito delle politiche che supportano sia autorizzazione positive sia autorizzazioni negative, cosa si intende per inconsistenza e non completezza? Come si possono risolvere tali problemi?
GIA' RISPOSTO NELLA DOMANDA 6

## 42 - Nell'ambito delle tecniche per la verifica della integrità del risultato di query, si richiede di descrivere le differenze principali tra le tecniche deterministiche e le tecniche probabilistiche. Si richiede inoltre di fare un esempio di query e come si usa una tecnica deterministica per verificarne il risultato
GIA' RISPOSTO NELLA DOMANDA 11

## 43 - Nell'ambito delle politiche mandatorie, si richiede di descrivere le politiche alternative al modello di Biba
Il modello **Biba** può essere rilassato:
- **Low-watermark for subjects (no write up)**: non ho vincoli in lettura
	- un soggetto **S** può scrivere un oggetto **O** solo se la classe di **S** domina la classe di **O**
	- un soggetto **S** può leggere qualsiasi oggetto **O**
	- dopo una lettura la classe del soggetto **S** diventa il **glb** tra la classe del soggetto **S** e la classe dell'oggetto **O**
- **Low-watermark for objects (no read down)**: non ho vincoli in scrittura
	- un soggetto **S** può leggere un oggetto **O** solo se la classe di **O** domina la classe di **S**
	- un soggetto **S** può scrivere qualsiasi oggetto **O**
	- dopo una scrittura la classe dell'oggetto **O** diventa il **glb** tra la classe del soggetto **S** e la classe dell'oggetto **O**

## 44 - Nell'ambito delle tecniche di verifica della integrità del risultato di query, si richiede di descrivere la tecnica basata sull'uso delle skip list anche tramite un semplice esempio
Una **skip list** per un insieme **S** di elementi distinti (chiavi) è una serie di liste $S_0$, $S_1$, ..., $S_k$ tali che:
- $S_0$ contiene tutti i dati ordinati in ordine non decrescente insieme a due valori sentinella -infinito e +infinito
- $S_i$, per ogni i = 1, ..., k contiene un sottoinsieme degli elementi in $S_{i-1}$ con una certa probabilità *P* (per esempio 1/2) (anche qui ci sono sempre i valori sentinella)

**Operazione di ricerca**:
- si parte dal valore sentinella nella lista più in alto
- si procede orizzontalmente finchè l'elemento corrente è il più grande elemento minore o uguale al target (esempio, sto cercando 9. Se trovo un 10 allora torno all'elemento precedente e scendo di una lista)
- si scende di lista finchè non si raggiunge la lista $S_0$

## 45 - Nell'ambito delle tecniche di verifica della integrità del risultato di query, a cosa servono i sali e i bucket nel caso di join 1 a molti?
Servono a distruggere combinazioni riconoscibili (frequenze di apparizione) nei join 1 a molti:
- **Salts**: mappano differenti occorrenze dello stesso valore di join dalla parte "molti" ad un differente valore cifrato usando un sale diverso. Replicano ogni tupla dal lato "1" del join e combinano le repliche con sali diversi per garantirne il match
- **Buckets**: inseriscono tuple di scarto "dummy" dalla parte "molti" del join per garantire una distribuzione delle frequenze "piatta" degli attributi di join

## 46 - Nell'ambito degli approcci per l'esecuzione di query in ambito distribuito, si richiede di descrivere il modello di autorizzazione basato su tre livelli di visibilità (plaintext, encrypted e no visibility). In particolare, si chiede di definire le autorizzazioni, descrivere il concetto di profilo di relazione (relation profile) e di dire quando un soggetto è autorizzato ad accedere ad una relazione. Si richiede inoltre di fare un semplice esempio di query con i relativi candidati
GIA' RISPOSTA NELLA DOMANDA 14

## 47 - Nell'ambito degli approcci per la specifica di requisiti utenti per la scelta di cloud plan, si richiede di descrivere i diversi approcci che possono essere adottati per determinare un ranking di piani (pareto, D e WD dominance). Si richiede anche di illustrare questi concetti tramite esempi
NON SO ANCORA RISPONDERE

## 48 - Nell'ambito della differential privacy, cosa si intende per global sensitivity? Si richiede di fare un esempio e di illustrare la relazione tra la global sensitivity ed il meccanismo di Laplace
GIA' RISPOSTA NELLE DOMANDE 36 e 21. La relazione tra **global sensitivity** e meccanismo di **Laplace** risiede nel fatto che per calcolare il valore di **λ** necessario a definire la scala della distribuzione di **Laplace**, occorre possedere **GS(A)** al numeratore e **ε** al denominatore. Più è grande **ε**, più piccolo sarà **λ** e quindi più grande sarà la probabilità di generare poco rumore