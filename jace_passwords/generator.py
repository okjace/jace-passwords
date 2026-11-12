"""Password generator: random characters, memorable passphrases, PINs — all from `secrets`."""
import math
import secrets
import string

WORDS = """
able acid acorn actor adapt admit adobe adult agent agile aisle alarm album alert alien alley
alpha amber amble ample anchor angel angle ankle apple april apron arena argue armor army aroma
arrow artist ash aspen atlas attic audio aunt autumn avid award awake axis bacon badge bagel
baker balmy bamboo banjo barn basil basin batch beach beacon beard beast bench berry bicycle
bingo birch bison blade blank blaze blend bliss blob bloom blue blunt blush board boast bonus
boost booth bored boss bottle boulder bounce brain brass brave bread breeze brick bride brief
bright brisk broom brush bubble bucket buddy bugle bunny burst butter cabin cable cactus cadet
camel camera canal candle candy canoe canvas canyon cape cargo carpet carrot carve castle cedar
cello chalk charm chart chase cheek cheese cherry chess chief chili chime chirp chorus cider
cinema circle citrus civic clam clap clay clerk cliff climb clock cloud clover coach coast cobra
cocoa comet comic coral corn cosmic cotton couch cougar cozy crab craft crane crater crayon
cream crisp crown crumb crust cubic curly cycle daily dairy daisy dance dandy dash dawn decoy
deep delta denim depot desert detour dial diary diesel dime diner disco dizzy docile dodge dolphin
donkey donut dough dove dragon drama dream drift drum duck dune dusk dwarf eager eagle easel
echo eclipse edge eel elbow elder elect elegant elk ember emerald empty energy engine envoy epic
equal erase error essay ethic event exact exile exotic expo fable fabric falcon fancy fargo
fawn feast feather fence fern ferry fetch fever fiber fiddle field fiesta finch fjord flame flash
flint flock flora floss flute focus foggy folk forest forge fossil fox frame fresh frog frost
fudge fungi funny gadget galaxy gallon gamma garden garlic gauge gecko gem genie giant ginger
giraffe glacier glad glass glide globe glory glove glow gnome goat gold golf goose gospel grain
grape graph grass gravel gravy great green grid grill grin groove group guava guest guide guitar
gumbo habit hammer hamster harbor harp hatch haven hawk hazel heart hedge helium helmet hero
heron hiker hill hippo hobby honey hood hook hope horizon horse hotel humble husky hybrid icicle
icon igloo image index indigo inlet input iris iron island ivory jacket jaguar jam jasper jazz
jelly jester jewel jigsaw jockey jolly journey judge juice jumbo jungle juniper kayak kebab kettle
khaki kiosk kitten kiwi koala label ladder lagoon lake lamp lantern laser latte lava lawn lemon
lens leopard lever lilac lily limber linen lion lizard llama lobby lobster locket lodge lotus
lucky lunar lunch lyric magic magnet mango manor maple marble march marsh mason meadow medal
melon mentor merit metal meteor mild mimic mint mirror mocha model modem molar monk moose mosaic
moss motel motor mouse muffin mural museum mystic nacho napkin nectar needle neon nest nickel
night noble nomad noodle north notch novel nugget nutmeg oasis oat ocean octave olive omega onion
opal opera orbit orchid organ otter outfit oval owl oxygen oyster paddle pagoda palace panda
panel panther papaya parade parrot pasta patch peach peanut pearl pebble pecan pedal pelican
penny pepper piano pickle pigeon pilot pine pirate pixel pizza plank planet plaza plum poem
polar pony poppy porch potato powder prairie prism puffin pulse pumpkin puppy puzzle python
quail quartz queen quest quick quiet quill quilt quiver rabbit radar radio radish raft rain
ramen ranch raven razor recipe reef relic remix rhino rhythm ribbon ridge rifle ripple river
robin robot rocket rodeo rose ruby rugby ruler rumble saddle safari saga salad salmon salsa
salt sandal satin sauna savvy scarf scout sealion season seed shadow shark shell sherpa shield
shrimp sierra silk silver siren sketch skunk slate sleek slogan sloth smile smoky snack snail
snow socket soda sofa solar sonic spark sphinx spice spider spiral splash sponge spoon spruce
squid stable stamp starch steam stellar stone stork storm straw stream studio sugar summit
sunny super surf swamp swan sweater swift syrup table tablet taco talon tango tapir tavern teapot
temple tennis thistle thunder tiger timber toast token tomato topaz torch toucan tower tractor
trail train tribe trophy tropic trout truffle tulip tuna tundra turtle tuxedo twig twilight
ultra umbrella unicorn union urban utopia valley vanilla vapor velvet venus verse vessel violet
viper visor vivid vocal volcano voyage wafer waffle walnut walrus wander wasabi water wave
whale wheat whisk widget willow window winter wizard wolf wombat wonder yacht yak yarn yeti yodel
yogurt zebra zenith zephyr zero zigzag zinc zipper zodiac zone
""".split()

SYMBOLS = "!@#$%^&*-_=+?.:"
AMBIGUOUS = set("Il1O0o|`'\"")


def random_password(length=20, upper=True, lower=True, digits=True, symbols=True, avoid_ambiguous=False) -> str:
    length = max(4, min(128, int(length)))
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        pools.append(string.ascii_lowercase)
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    alphabet = "".join(pools)
    # one from each chosen set, the rest from all of them, then shuffle
    chars = [secrets.choice(p) for p in pools[:length]]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def passphrase(words=5, separator="-", capitalize=True, number=True) -> str:
    words = max(3, min(12, int(words)))
    picked = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    if number:
        i = secrets.randbelow(words)
        picked[i] += str(secrets.randbelow(10))
    return separator.join(picked)


def pin(length=6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(max(4, min(12, int(length)))))


def generate(opts: dict) -> str:
    kind = opts.get("type", "random")
    if kind == "passphrase":
        return passphrase(opts.get("words", 5), opts.get("separator", "-"),
                          opts.get("capitalize", True), opts.get("number", True))
    if kind == "pin":
        return pin(opts.get("length", 6))
    return random_password(opts.get("length", 20), opts.get("upper", True), opts.get("lower", True),
                           opts.get("digits", True), opts.get("symbols", True), opts.get("avoidAmbiguous", False))


COMMON = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "111111", "iloveyou", "admin",
          "welcome", "monkey", "dragon", "football", "baseball", "sunshine", "princess", "passw0rd",
          "123456789", "1234567890", "000000", "password1", "qwerty123", "trustno1", "master", "hello"}


def strength(pw: str) -> dict:
    """Rough entropy estimate -> score 0..4 with a label."""
    if not pw:
        return {"score": 0, "bits": 0, "label": "Empty"}
    if pw.lower() in COMMON:
        return {"score": 0, "bits": 0, "label": "Very weak"}
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 33
    unique = len(set(pw))
    bits = len(pw) * math.log2(max(pool, 2)) * min(1.0, 0.5 + unique / max(len(pw), 1) / 2)
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    return {"score": score, "bits": round(bits), "label": ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score]}
