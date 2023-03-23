# Krypteringsprojekt ABB

Kod för diverse chiffer för användning vid enkryptering av bland annat text.

## Bygg

Programmet kan byggas med make (kräver GCC):

```sh
make
```

## Användning

Programmet kan köras i flera olika lägen för olika krypteringsmetoder. För att
lista alla tillgängliga metoder, kör programmet utan argument:

```sh
./encro
```

När programmet startas i ett läge får användaren mata in datan som ska
enkrypteras i klartext (och ibland nycklar om dessa inte genereras automatiskt)
och programmet ger tillbaka den enkrypterade chiffertexten samt informationen
som krävs för att dekryptera den.

Ex:
```sh
./encro aes
plaintext: hej
ciphertext: 73C4B21997E99E7FB040FF6A12241A26
key: 210C6D3D9D0F002BC098955FF211429C
iv: 89BB6F5DB76B40855D81738ED7D1FBF8
decrypted: hej
```

## Kryptografisk analys

Då majoriteten av de implementerade algoritmerna är enkla och även osäkra har
jag valt att endast analysera RSA och AES som är de modernaste metoderna som jag
implementerat.

### RSA

Rivest-Shamir-Adleman, ofta förkortat RSA, är en algoritm för assymetrisk
kryptering baserad på faktumet att det är svårt att faktorisera tal med stora
primtalsfaktorer.

Två (stora) primtal `p` och `q` genereras och deras produkt kallas `n`. En
enkryptionsnyckel `e` beräknas så att `2 < e < λ(n)`, och `e` och `λ(n)` är
relativt prima, där `λ(n)` är Carmichaels totientfunktion av `n` (i koden
används Eulers totientfunktion som är lättare att beräkna och har samma
egenskaper, men är större). Kort bit-längd och låg Hammingvikt ger en
effektivare enkryption, och då `e` är del av den offentliga nyckeln och därmed
inte hemlig hårdkodas den till `65537` (2 i Hammingvikt samt 17 i bit-längd men
inte litet nog för att utgöra en säkerhetsrisk). Det är ett primtal och är
därför alltid relativt primt med `λ(n)`.

Dekryptionsnyckeln `d` räknas ut av den modulära inversen av `e` med modulen
`λ(n)`. Detta gör att `x^(e*d) ≡ x (mod n)`, enligt Fermats lilla sats. Ett
heltal `m` kan då krypteras till `c` genom formeln `m^e ≡ c (mod n)`, vilket
senare kan dekrypteras med `d` på samma sätt: `c^d = m^(e*d) ≡ m (mod n)`. Paret
`(e, n)` krävs vid enkryptering och kallas för den offentliga nyckeln, paret
`(d, n)` krävs vid dekryptering och kallas för den privata nyckeln. Någon med
Bobs offentliga nyckel kan enkryptera ett meddelande som endast Bob kan läsa med
sin privata nyckel.

Denna algoritm fungerar endast där `m` är ett heltal mellan `0` och `n-1`, och
då blir `c` ett annat heltal mellan `0` och `n-1`. Allting utanför det
intervallet kommer att "loopa" på grund av den cykliska naturen av modulär
aritmetik. På grund av denna begränsning är RSA inte lämpligt för enkryptering
av text, då det inte är lätt att representera i just den formen. Det går att
enkryptera text byte-för-byte, men eftersom det endast ger 256 unika värden på
`c` (och varje byte ger samma `c`) så är det ekvivalent med ett enkelt
substitutionschiffer.  Metoden använder även onödigt med utrymme då varje `c`
kan vara upp till `n-1` och ta mycket mer plats än en byte, speciellt med stora
nycklar. För att lösa dessa problem kan man enkryptera text i större block, men
det löser inte alla problem, till exempel man-in-the-middle attacker då
enkryptionsnyckeln är offentlig och blocken inte beror av varandra.

Det man kan göra är att använda faktumet att RSA är en assymetrisk algoritm för
att göra en nyckelöverföring av en symmetrisk nyckel. Därefter kan man
kommunicera via ett symmetriskt chiffer som AES. Denna metod är säker så länge
ingen som lyssnar av trafiken kan primtalsfaktorisera `n` och räkna ut
dekryptionsnyckeln. Den snabbaste klassiska algoritmen för primtalsfaktorisering
är det generella talsållet som kör i super-polynom, men sub-exponentiell tid.
Alltså ökar tiden för faktorisering (nästan) exponentiellt när talet växer,
vilket gör det praktiskt omöjligt att faktorisera tal i storleksordningen som
brukar användas vid RSA (men triviellt för storleken av tal jag använder). Dock
finns en snabbare kvantalgoritm, Shors algoritm, som kan faktorisera ett tal i
polylogaritmisk tid, vilket kan orsaka problem inom 5--10 år när antalet
kvantbitar i kvantdatorer ökat tillräckligt.

#### Kommentar om primtalsgenerering

Min implementation genererar primtal på 16 bitar (endast för att varje
individuell beräkning ska resultera i ett tal som får plats i ett 64 bitars
ord). Då den mest värda biten alltid är satt för att bit-längden ska vara 16 och
då den minst värda biten alltid är satt eftersom primtalet inte kan vara delbart
med 2 så krävs endast 14 slumpade bitar. 

Ett potentiellt primtal genereras slumpmässigt enligt metoden i föregående
stycke, och testas sedan för delbarhet med de första hundra primtalen. Sedan
används en probabilistisk metod (Rabin-Miller) för att snabbt bli hyfsat säker
att det är ett primtal. Om något av testen misslyckas genereras ett nytt tal.

För 16 bitars tal är det fortfarande möjligt att göra ett snabbt deterministisk
test, men för tal i storleksordningen som räknas som säker att använda i RSA är
detta inte möjligt. Därför används probabilistiska test för att vara så säker
att det potentiella primtalet faktiskt är ett primtal som krävs för
användningsområdet.

### AES

AES (Advanced Encryption Standard) är en variant av Rijndael med fixerad block-
och nyckelstorlek. Det är ett symmetriskt substitutions-permutationskrypto,
alltså krypteras blocken genom att växelvis substituera och permutera bytes.
Blockstorleken är 128 bitar, och representeras som en 4 gånger 4 matris av 16
bytes ("column-major" ordning), nyckelstorleken i min kod är 128 bitar, men kan
även vara 196 eller 256 bitar. Då meddelandet måste delas upp i block så fylls
det ut enligt PKCS #7 för att storleken ska vara jämnt delbar med 16 bytes.

Varje substitution-permutation kallas för en runda och antalet rundor beror av
nyckelstorleken, i fallet med en 128 bitars nyckel används 10 rundor. Alla
rundor krypteras med en unik nyckel, som genereras i "nyckelexpansionen" från
huvudnyckeln. Det görs genom att dela upp huvudnyckeln i fyra 32 bitars ord och
att beräkna fler ord genom exklusiv disjunktion (XOR) och
substitution-permutation av tidigare ord i uppställningen. Resultatet är en
uppställning av huvudnyckeln följt av alla rundnycklar.

Innan rundorna adderas huvudnyckeln till blocket (alla beräkningar sker i
Galoiskroppen `GF(2^8)` där addition reduceras modulo 2 och är därmed ekvivalent
med exklusiv disjunktion). Alla resterande rundor följer samma mönster:
teckensubstitution, radskiftning, kolumnblandning, följt av nyckeladdition. Enda
undantaget är sista rundan som inte har en kolumnblandning.

Teckensubstitutionen byter ut varje byte mot en annan byte, implementerad med en
såkallad S-box. Värdena är specifikt valda (beräknade med linjär algebra) för
att tillföra konfusion, alltså att göra kopplingen mellan chiffertexten och
nyckeln otydligare.

Radskiftningen skiftar varje rad i matrisen för att förhindra att alla kolumner
krypteras separat, vilket skulle reducera algoritmen till fyra separata
blockchiffer. Tillsammans med kolumnblandning tillför den även diffusion, alltså
att varje del av klartexten påverkar varje del av chiffertexten.

Kolumnblandningen innebär att varje kolumn i matrisen genomgår en
matrismultiplikation (fortfarande i Galoiskroppen `GF(2^8)`). Som tidigare nämnt
är detta steg till för att tillföra mer diffusion.

Sista steget är nyckeladditionen, som implementeras på exakt samma sätt som
additionen av huvudnyckeln innan första rundan, fast med rundans unika nyckel
istället. Detta steget introducerar nyckeln i varje runda vilket omöjliggör
förhandsberäkning av rundorna utan nyckeln.

AES är av sig självt ett EBC chiffer, alltså enkrypteras alla block enskilt,
vilket gör att det inte finns någon diffusion mellan blocken. Det gör att stora
mönster i klartexten syns tydligt i chiffertexten. Likt andra blockchiffer kan
man använda andra metoder för att skapa ett beroende mellan blocken och
introducera diffusion. Metoden som används i min kod är CBC, där varje blocks
klartext XOR-as med föregående blocks chiffertext (eller en startvariabel för
första blocket).

AES har till skillnad från RSA inga uppenbara säkerhetsbrister eller opraktiska
egenskaper vid kryptering av text. Chiffret har mycket bra konfusion och
diffusion vilket gör statistisk och annan matematisk analys mycket svår. Med
andra ord syns inte mönster i klartexten över huvud taget i chiffertexten. Vad
jag kan hitta finns några attacker formulerade som skulle vara snabbare än brute
force, men ingen som är snabb not för att vara praktiskt applicerbar. Alltså
ligger den största risken hos människan och/eller nyckelöverföringen.

## Övrig Kommentar

Angående "kommenterad kod" så anser jag att min kod är hyfsat
självdokumenterande. Funktioner gör vad namnen säger och argumentens syfte är
tydliga endast baserat på deras namn. Kommentarer finns där de finns för att
kommentera på den kod som är skriven, vare sig det är en påminnelse eller en
förklaring för ett högst otydligt kodblock. Att hjärndött skriva en kommentar
som förklarar vad varje detalj gör är något jag inte tror är produktivt och som
inte tillför något till kodens läsbarhet eller förståelighet, och är därmed
något jag inte gör av princip.
