#include "secure_identity.h"


namespace upw
{

void EC_SharedSecret::Compute(const EC_PublicKey& pub, const EC_PrivateKey& pri)
{
	DataBlock<32, true> p2;
	crypto_scalarmult_curve25519_base(p2, pri);
	crypto_scalarmult_curve25519(*this, pri, pub);
	(*this) ^= p2;
	(*this) ^= (const DataBlock<32, true>&)pub;
}

bool EC_Cryptography::Decrypt(const EC_Nonce& n, LPCVOID cipher, SIZE_T cipher_len, LPVOID plaintext) const
{
	return 0 == crypto_box_open_detached_afternm((LPBYTE)plaintext, 
													((LPCBYTE)cipher) + crypto_box_MACBYTES,
													(LPCBYTE)cipher,
													cipher_len - crypto_box_MACBYTES,
													n, _nm);
}


namespace _details
{
static const uint32_t MnemonicDictSize = 4096;
static const uint32_t MnemonicBitBlock = 12;
static const rt::SS g_MnemonicDict[MnemonicDictSize] =
{
	"abandon", "abbey", "abdomen", "aber", "abide", "ability", "able", "abnormal", "aboard", "abort", "about", "above", "abroad", "absent", "absorb", "abstract",  	// 0x00 - 0x0f
	"abundant", "abusive", "academy", "access", "accident", "account", "accrue", "accuse", "acdbline", "acer", "achieve", "acid", "acne", "acoustic", "acquire", "acre",  	// 0x10 - 0x1f
	"across", "acrylic", "acted", "action", "actor", "actress", "acts", "actual", "acura", "acute", "adam", "adapter", "added", "adding", "address", "adds",  	// 0x20 - 0x2f
	"adele", "adequate", "adhere", "adidas", "adipex", "adjacent", "adjust", "admin", "adobe", "adolf", "adopt", "adrian", "adsl", "advance", "adverse", "advice",  	// 0x30 - 0x3f
	"advocacy", "adware", "aerial", "aero", "affair", "affect", "affiliate", "afford", "afghan", "afraid", "after", "against", "aged", "agent", "ages", "aggregate",  	// 0x40 - 0x4f
	"aging", "agree", "aguilar", "aids", "aimed", "aims", "airbus", "aircraft", "aire", "airfare", "airline", "airport", "airway", "ajax", "alan", "alarm",  	// 0x50 - 0x5f
	"alba", "albert", "album", "alcatel", "alcohol", "alert", "alex", "alfa", "alfred", "algebra", "algorithm", "alice", "alien", "align", "alike", "alison",  	// 0x60 - 0x6f
	"alito", "alive", "alkali", "alle", "allow", "ally", "almost", "along", "alot", "aloud", "alphabet", "alpine", "already", "alright", "also", "alter",  	// 0x70 - 0x7f
	"although", "altima", "alto", "alumni", "always", "alzheimer", "amazon", "amber", "ambien", "ambush", "amend", "america", "amino", "amnesty", "among", "amount",  	// 0x80 - 0x8f
	"ample", "amps", "amsterdam", "amuse", "anaheim", "anatomy", "ance", "anchor", "ancient", "andale", "anderson", "andorra", "andre", "andy", "angel", "angle",  	// 0x90 - 0x9f
	"angola", "angry", "angus", "anime", "ankle", "anna", "anne", "annie", "announce", "annual", "anonymous", "another", "ansi", "answer", "antarctic", "ante",  	// 0xa0 - 0xaf
	"anthem", "anti", "anton", "anxiety", "anybody", "anymore", "anyone", "anytime", "anyway", "apache", "apartment", "aperture", "apex", "aphrodite", "apnic", "apollo",  	// 0xb0 - 0xbf
	"apparel", "appear", "apply", "appoint", "approx", "apps", "april", "aqua", "arbitrary", "arbor", "arcade", "archive", "arctic", "area", "argentina", "args",  	// 0xc0 - 0xcf
	"argue", "arise", "arizona", "arkansas", "arlington", "armed", "armor", "arms", "army", "arnold", "aroma", "around", "array", "arrest", "arrive", "arrow",  	// 0xd0 - 0xdf
	"arthur", "artist", "arts", "artwork", "asap", "asbestos", "ascent", "ascii", "asha", "ashley", "asia", "aside", "asin", "asked", "asking", "asks",  	// 0xe0 - 0xef
	"asleep", "aspen", "asphalt", "assay", "asset", "assist", "associate", "assume", "aster", "asthma", "aston", "astro", "asus", "asylum", "athens", "athlon",  	// 0xf0 - 0xff
	"atkin", "atlantic", "atom", "attach", "attend", "attic", "attorney", "attract", "auckland", "auction", "audio", "august", "aunt", "aurora", "aussi", "austin",  	// 0x0100 - 0x010f
	"author", "autism", "auto", "autumn", "auxiliary", "available", "avalon", "avenue", "average", "aviation", "avid", "avoid", "avon", "avril", "await", "award",  	// 0x0110 - 0x011f
	"away", "awesome", "awful", "axis", "baby", "bach", "back", "bacon", "bacteria", "badge", "badly", "baghdad", "bags", "bahrain", "bail", "bake",  	// 0x0120 - 0x012f
	"balance", "balcony", "bald", "bali", "ball", "baltic", "bamboo", "banana", "band", "bang", "bank", "banner", "banquet", "barb", "barcode", "bare",  	// 0x0130 - 0x013f
	"bargain", "bark", "barn", "baron", "barr", "bars", "bart", "base", "bash", "basic", "basket", "bass", "batch", "bate", "bath", "batman",  	// 0x0140 - 0x014f
	"baton", "battle", "bauer", "bdsm", "beach", "bead", "beam", "bean", "bear", "beat", "beauty", "became", "beck", "become", "bedding", "bedford",  	// 0x0150 - 0x015f
	"bedroom", "beds", "beef", "been", "beer", "began", "begin", "begun", "behalf", "behind", "beige", "beijing", "being", "belarus", "belfast", "belgium",  	// 0x0160 - 0x016f
	"belief", "belkin", "bell", "belmont", "below", "belt", "bench", "bend", "benefit", "benin", "benjamin", "benny", "benq", "benson", "bent", "benz",  	// 0x0170 - 0x017f
	"berkeley", "berlin", "berman", "bern", "berry", "beside", "best", "beta", "beth", "bets", "better", "between", "beverly", "beware", "beyond", "bhutan",  	// 0x0180 - 0x018f
	"bias", "biblical", "bibtex", "bicycle", "bidder", "bids", "biggest", "bike", "bikini", "bilateral", "bility", "bill", "binary", "bind", "bing", "binomial",  	// 0x0190 - 0x019f
	"biochem", "biodiesel", "biography", "biol", "biomed", "bios", "biotech", "bird", "birth", "bishop", "bissau", "bite", "bits", "bizarre", "bizrate", "blade",  	// 0x01a0 - 0x01af
	"blah", "blair", "blake", "blame", "blank", "blast", "bldg", "bleed", "blend", "bless", "blink", "bliss", "block", "blog", "blond", "blood",  	// 0x01b0 - 0x01bf
	"blue", "bluff", "blunt", "blvd", "bnet", "board", "boat", "body", "boeing", "bois", "bold", "bolivia", "boll", "bolt", "bomb", "bond",  	// 0x01c0 - 0x01cf
	"bone", "bonn", "bonus", "book", "bool", "boost", "boot", "border", "bore", "boris", "born", "boro", "borrow", "bosch", "bosnia", "boss",  	// 0x01d0 - 0x01df
	"boston", "botany", "both", "bots", "bottom", "bought", "boulder", "bound", "bouquet", "bout", "bowl", "boxes", "boxing", "boyd", "boyfriend", "boys",  	// 0x01e0 - 0x01ef
	"brace", "brad", "brain", "brake", "brand", "bras", "brave", "brazil", "break", "bree", "brent", "bret", "brian", "brick", "bride", "brief",  	// 0x01f0 - 0x01ff
	"bright", "brilliant", "bring", "bristol", "british", "broad", "brock", "broke", "bronx", "brook", "brother", "brought", "brown", "bruce", "bruno", "brush",  	// 0x0200 - 0x020f
	"brut", "bryan", "bubble", "buck", "budapest", "buddy", "budget", "buena", "buff", "bufing", "bugs", "buick", "build", "bukkake", "bulb", "bulgaria",  	// 0x0210 - 0x021f
	"bulk", "bull", "bump", "bunch", "bundle", "bunn", "burden", "bureau", "burial", "burke", "burley", "burma", "burst", "burt", "burundi", "buses",  	// 0x0220 - 0x022f
	"bush", "business", "bust", "busy", "butler", "buyer", "buying", "buys", "buzz", "bypass", "byron", "byte", "cabin", "cable", "cache", "cadiz",  	// 0x0230 - 0x023f
	"cafe", "cage", "caicos", "cair", "cake", "calcium", "calendar", "calgary", "call", "calm", "calorie", "calvin", "cambodia", "camcorder", "camden", "came",  	// 0x0240 - 0x024f
	"camp", "cams", "canada", "canberra", "cancel", "candy", "cane", "canna", "canon", "cant", "canvas", "canyon", "capable", "cape", "capital", "capri",  	// 0x0250 - 0x025f
	"caps", "capture", "cara", "carb", "carcass", "card", "care", "cargo", "carl", "carmen", "carney", "carol", "carp", "carr", "cars", "cart",  	// 0x0260 - 0x026f
	"carve", "casa", "cascade", "case", "cash", "casino", "cass", "cast", "casual", "catalog", "catchy", "category", "cath", "cats", "cattle", "caught",  	// 0x0270 - 0x027f
	"cause", "caution", "cave", "cayman", "cctv", "cdna", "cease", "cedar", "ceiling", "celeb", "cell", "celtic", "cement", "census", "center", "ceramic",  	// 0x0280 - 0x028f
	"cereal", "cern", "certain", "cest", "chad", "chair", "challenge", "champ", "change", "chao", "chapel", "char", "chase", "chat", "cheap", "check",  	// 0x0290 - 0x029f
	"cheer", "chef", "chelsea", "chem", "chen", "cheque", "cher", "chest", "chevy", "chick", "chief", "child", "chip", "chirac", "chloe", "chocolate",  	// 0x02a0 - 0x02af
	"choice", "choose", "chop", "chord", "chose", "chris", "chrome", "chrysler", "chubby", "cialis", "ciao", "cigar", "cindy", "cinema", "cingular", "cinnamon",  	// 0x02b0 - 0x02bf
	"circle", "citadel", "cite", "citrus", "city", "civil", "claim", "clam", "clan", "clark", "class", "claus", "clay", "clear", "clerk", "clever",  	// 0x02c0 - 0x02cf
	"clic", "client", "cliff", "climb", "clinic", "clip", "clock", "clone", "close", "cloth", "cloud", "club", "clue", "cluster", "clutch", "cnet",  	// 0x02d0 - 0x02df
	"coaches", "coal", "coast", "coat", "cobra", "coca", "coco", "code", "coffee", "cognitive", "cohen", "coil", "coin", "coke", "cola", "cold",  	// 0x02e0 - 0x02ef
	"cole", "coli", "college", "color", "column", "combo", "come", "comfort", "common", "como", "company", "concept", "conduct", "cone", "config", "congo",  	// 0x02f0 - 0x02ff
	"conjugate", "connect", "conrad", "const", "contact", "convey", "conwy", "cook", "cool", "coop", "cope", "copper", "cops", "copy", "cord", "core",  	// 0x0300 - 0x030f
	"cork", "corn", "corona", "corp", "correct", "corvette", "cosmic", "cosplay", "cost", "cote", "cotton", "cough", "could", "count", "coupe", "court",  	// 0x0310 - 0x031f
	"cousin", "cover", "cowboy", "cows", "crab", "crack", "cradle", "craft", "craig", "crane", "crawl", "crazy", "cream", "credit", "creek", "crest",  	// 0x0320 - 0x032f
	"crew", "crib", "cricket", "cried", "crim", "crisp", "critic", "croatia", "crop", "cross", "crow", "crucial", "crude", "crue", "cruise", "crush",  	// 0x0330 - 0x033f
	"cruz", "crystal", "ctrl", "cuba", "cube", "cubs", "cuisine", "culinary", "culture", "cumbria", "cups", "curb", "cure", "curious", "curl", "current",  	// 0x0340 - 0x034f
	"curse", "curt", "curve", "cushion", "custom", "cute", "cutie", "cuts", "cutter", "cyber", "cycle", "cygwin", "cylinder", "cynthia", "cyprus", "czech",  	// 0x0350 - 0x035f
	"daemon", "daewoo", "daily", "dairy", "daisy", "dakota", "dale", "dallas", "damage", "dame", "dana", "dance", "danger", "daniel", "danny", "dans",  	// 0x0360 - 0x036f
	"dare", "dark", "darla", "darren", "darwin", "dash", "data", "date", "daughter", "dave", "davis", "dawn", "dawson", "daylight", "days", "dayton",  	// 0x0370 - 0x037f
	"deaf", "deal", "dean", "dear", "debate", "debbie", "debit", "deborah", "debra", "debt", "debug", "decay", "december", "decide", "deck", "decline",  	// 0x0380 - 0x038f
	"deco", "decrease", "dedicate", "deduct", "deed", "deem", "deep", "deer", "default", "defend", "define", "degree", "delay", "delete", "delhi", "deliver",  	// 0x0390 - 0x039f
	"dell", "delphi", "delta", "deluxe", "demand", "demo", "denim", "denmark", "denny", "denon", "dense", "dent", "denver", "deny", "depend", "deploy",  	// 0x03a0 - 0x03af
	"depot", "deprive", "dept", "deputy", "derby", "derek", "derive", "describe", "desert", "design", "desk", "despite", "dessert", "destiny", "detail", "detect",  	// 0x03b0 - 0x03bf
	"detroit", "deutsch", "develop", "device", "devon", "dewey", "diablo", "diagram", "dial", "diamond", "diane", "diaper", "diary", "diaz", "dice", "didrex",  	// 0x03c0 - 0x03cf
	"diego", "diet", "diff", "digest", "digg", "digital", "dignity", "dilemma", "dimension", "dining", "dinner", "dioxin", "diploma", "direct", "dirt", "disable",  	// 0x03d0 - 0x03df
	"disc", "dish", "disk", "dismal", "disney", "disorder", "display", "diss", "district", "dive", "divorce", "divx", "dixon", "djibouti", "dock", "docs",  	// 0x03e0 - 0x03ef
	"doctor", "document", "does", "dogs", "doing", "dolby", "doll", "dolphin", "domain", "dome", "domino", "donate", "done", "donna", "donor", "dont",  	// 0x03f0 - 0x03ff
	"door", "dorothy", "dorset", "dosage", "dose", "dots", "doubt", "doug", "dove", "down", "doyle", "dozen", "draft", "drag", "drain", "drake",  	// 0x0400 - 0x040f
	"drama", "draw", "dream", "dress", "drew", "drift", "drill", "drink", "drive", "drop", "drove", "drum", "dryer", "dual", "dubai", "dublin",  	// 0x0410 - 0x041f
	"duck", "dude", "duff", "duke", "dummy", "dump", "duncan", "dundee", "dunn", "duplex", "durable", "durham", "during", "dust", "dutch", "duty",  	// 0x0420 - 0x042f
	"dvds", "dwell", "dying", "dylan", "dynamic", "each", "eagle", "early", "earn", "earring", "ears", "earth", "ease", "easily", "east", "easy",  	// 0x0430 - 0x043f
	"eating", "ebay", "ebony", "ebook", "ecard", "echo", "eclipse", "ecology", "ecommerce", "economy", "ecosystem", "ecuador", "eden", "edgar", "edge", "edinburgh",  	// 0x0440 - 0x044f
	"edison", "edit", "edmond", "education", "edward", "edwin", "effect", "efficacy", "effort", "eggs", "egypt", "eight", "einstein", "either", "elaborate", "elaine",  	// 0x0450 - 0x045f
	"elastic", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevate", "eligible", "eliminate", "elizabeth", "ellis", "else", "elvis", "emac", "email",  	// 0x0460 - 0x046f
	"embark", "embedded", "embryo", "emerald", "emil", "eminem", "emirates", "emission", "emma", "emotion", "emperor", "emphasis", "empire", "employee", "empty", "enable",  	// 0x0470 - 0x047f
	"enact", "encarta", "enclose", "encore", "encrypt", "endanger", "endif", "endl", "endo", "ends", "energy", "enforce", "engage", "engine", "english", "enhance",  	// 0x0480 - 0x048f
	"enjoy", "enlarge", "enom", "enormous", "enough", "enquiry", "enron", "ensembl", "ensure", "enter", "entire", "entry", "envelope", "enzyme", "epic", "epidemic",  	// 0x0490 - 0x049f
	"epinions", "episode", "epson", "equal", "equity", "eric", "erie", "erik", "erin", "eritrea", "ernest", "eros", "erotic", "error", "escape", "espn",  	// 0x04a0 - 0x04af
	"esprit", "essay", "essential", "estate", "estimate", "estonia", "eternal", "ethernet", "ethic", "etiquette", "eureka", "euro", "eval", "evan", "even", "ever",  	// 0x04b0 - 0x04bf
	"evident", "evil", "evolve", "exact", "exam", "except", "exchange", "excite", "exclude", "excuse", "executive", "exempt", "exercise", "exhaust", "exhibit", "exist",  	// 0x04c0 - 0x04cf
	"exit", "exodus", "exotic", "expand", "expert", "expire", "explore", "expo", "express", "exquisite", "extent", "extra", "eyed", "eyes", "fabric", "fabulous",  	// 0x04d0 - 0x04df
	"face", "fact", "faculty", "fade", "fail", "fair", "faith", "fake", "falco", "falk", "fall", "false", "fame", "family", "famous", "fancy",  	// 0x04e0 - 0x04ef
	"fans", "fantasy", "faqs", "fare", "fargo", "farm", "fascia", "fashion", "faso", "fast", "fatal", "fate", "father", "fatima", "fatty", "fault",  	// 0x04f0 - 0x04ff
	"fave", "favor", "faxes", "feast", "feature", "february", "federal", "fedora", "feed", "feel", "fees", "feet", "fell", "felt", "female", "femdom",  	// 0x0500 - 0x050f
	"feminist", "fence", "fend", "feof", "fergus", "ferry", "fertile", "fest", "fever", "fewer", "fgets", "fiber", "fibre", "fiction", "fide", "field",  	// 0x0510 - 0x051f
	"fiesta", "fifteen", "fight", "figure", "fiji", "file", "fill", "film", "filter", "final", "find", "fine", "finger", "finish", "finland", "finn",  	// 0x0520 - 0x052f
	"fiori", "fire", "firm", "first", "fiscal", "fish", "fist", "fitness", "fits", "fitted", "fitz", "five", "fixe", "fixture", "flag", "flame",  	// 0x0530 - 0x053f
	"flash", "flat", "flavor", "flee", "flesh", "flew", "flex", "flick", "flight", "flip", "float", "flop", "florida", "flour", "flow", "floyd",  	// 0x0540 - 0x054f
	"fluctuate", "fluid", "fluoride", "flush", "flute", "flux", "flyer", "flying", "foam", "focal", "focus", "foil", "fold", "folk", "follow", "font",  	// 0x0550 - 0x055f
	"food", "fool", "foot", "forbes", "force", "ford", "forge", "fork", "form", "fort", "forum", "forward", "foss", "foster", "foto", "fought",  	// 0x0560 - 0x056f
	"foul", "found", "four", "fractal", "fragile", "frame", "frank", "fraser", "freak", "fred", "free", "freight", "fremont", "french", "frequent", "fresh",  	// 0x0570 - 0x057f
	"friday", "friend", "fringe", "frog", "from", "front", "frost", "frozen", "fruit", "frustrate", "fuel", "fuji", "fulfil", "full", "fulton", "function",  	// 0x0580 - 0x058f
	"fund", "funk", "funny", "furniture", "further", "fury", "fusion", "future", "fuzz", "gabon", "gabriel", "gadget", "gage", "gain", "gala", "gale",  	// 0x0590 - 0x059f
	"gallery", "gals", "gambia", "game", "gamma", "gang", "gaps", "garage", "garbage", "garcia", "garden", "garlic", "garmin", "garnet", "garry", "gary",  	// 0x05a0 - 0x05af
	"gases", "gasoline", "gate", "gather", "gauge", "gave", "gays", "gaza", "gaze", "gear", "geek", "geforce", "gemini", "gems", "gender", "gene",  	// 0x05b0 - 0x05bf
	"genoa", "genre", "gent", "genus", "geoff", "geography", "geology", "geometry", "george", "gerald", "getaway", "gets", "getting", "ghana", "ghetto", "ghost",  	// 0x05c0 - 0x05cf
	"giant", "gibraltar", "gibson", "gift", "gilbert", "gill", "ginger", "girl", "give", "glad", "gland", "glass", "glen", "globe", "glory", "gloss",  	// 0x05d0 - 0x05df
	"glove", "glow", "glucose", "glue", "gmbh", "gnome", "goal", "goat", "goddess", "gods", "goes", "gold", "golf", "gone", "gonna", "good",  	// 0x05e0 - 0x05ef
	"google", "goose", "gordon", "gore", "gorgeous", "gorilla", "gospel", "goss", "goth", "goto", "gotta", "gourmet", "govt", "gprs", "grab", "grace",  	// 0x05f0 - 0x05ff
	"grad", "graham", "grain", "gram", "grand", "graph", "gras", "gratis", "grave", "gray", "great", "green", "greg", "grenada", "grew", "grey",  	// 0x0600 - 0x060f
	"grid", "grief", "griffin", "grill", "grip", "grocery", "groom", "group", "grove", "grow", "guadalupe", "guam", "guard", "guatemala", "gucci", "guest",  	// 0x0610 - 0x061f
	"guide", "guild", "guinea", "guitar", "gulf", "guns", "guru", "guyana", "guys", "gwen", "gymnast", "gzip", "habit", "hack", "haha", "hair",  	// 0x0620 - 0x062f
	"haiti", "half", "halifax", "hall", "halo", "hamburg", "hamilton", "hammer", "hampton", "hand", "hang", "hanna", "hans", "happy", "harass", "harbor",  	// 0x0630 - 0x063f
	"hard", "harley", "harm", "harness", "harold", "harp", "harry", "hart", "harvey", "hash", "hassle", "hast", "hate", "hath", "hatred", "hats",  	// 0x0640 - 0x064f
	"haunt", "have", "hawaii", "hawk", "hayes", "hazard", "hdtv", "head", "health", "hear", "heat", "heavy", "hebrew", "heck", "hedge", "heel",  	// 0x0650 - 0x065f
	"height", "held", "helen", "heli", "helm", "help", "helsing", "hence", "hendrix", "henry", "hentai", "hepa", "herald", "herb", "here", "heritage",  	// 0x0660 - 0x066f
	"herman", "hero", "hers", "herzog", "hesitate", "hewitt", "hewlett", "hidden", "hide", "hier", "hifi", "high", "hike", "hilary", "hill", "hilton",  	// 0x0670 - 0x067f
	"himself", "hind", "hint", "hire", "hispanic", "history", "hitachi", "hits", "hitter", "hobart", "hobby", "hockey", "hoff", "hogtied", "hold", "holiday",  	// 0x0680 - 0x068f
	"holly", "holm", "hologram", "holy", "home", "honda", "honey", "hong", "honor", "hood", "hoover", "hope", "hopkins", "horizon", "hormone", "horowitz",  	// 0x0690 - 0x069f
	"horror", "horse", "hose", "hospital", "host", "hotel", "hotlog", "hotmail", "hottie", "hotwire", "houghton", "hour", "house", "howard", "however", "howto",  	// 0x06a0 - 0x06af
	"href", "html", "http", "hubs", "hudson", "huge", "hugh", "hugo", "hull", "human", "humble", "humid", "humor", "hundred", "hung", "hunk",  	// 0x06b0 - 0x06bf
	"hunt", "hurry", "hurt", "husband", "hussein", "hutchins", "hyatt", "hybrid", "hyde", "hydro", "hygiene", "hype", "hypocrisy", "hyundai", "icann", "iceland",  	// 0x06c0 - 0x06cf
	"icon", "idaho", "idea", "identify", "ideology", "idle", "idol", "ieee", "ietf", "ignite", "ignore", "illinois", "illness", "illusion", "image", "imdb",  	// 0x06d0 - 0x06df
	"immediate", "imminent", "immune", "impact", "imperial", "imply", "import", "improve", "impure", "inability", "inactive", "inbox", "incense", "inch", "incident", "include",  	// 0x06e0 - 0x06ef
	"income", "increase", "incur", "index", "indian", "indoor", "industry", "infant", "infect", "infinite", "influence", "info", "infrared", "ingram", "inhale", "inherit",  	// 0x06f0 - 0x06ff
	"inhibit", "init", "inject", "injury", "inkjet", "inlay", "inlet", "inner", "innocent", "inns", "input", "inquiry", "insane", "insert", "inside", "inspire",  	// 0x0700 - 0x070f
	"instead", "insurance", "intake", "internet", "intimate", "intl", "into", "intro", "intuit", "invade", "invest", "invite", "involve", "iowa", "ipaq", "ipod",  	// 0x0710 - 0x071f
	"iran", "iraq", "ireland", "iris", "iron", "irregular", "irritable", "irvine", "isaac", "isbn", "isdn", "islam", "isle", "isolate", "isps", "issn",  	// 0x0720 - 0x072f
	"issue", "istanbul", "isuzu", "italy", "item", "itinerary", "itself", "itunes", "ivan", "ivoire", "ivory", "jack", "jacob", "jacque", "jacuzzi", "jaguar",  	// 0x0730 - 0x073f
	"jail", "jakarta", "jake", "jamaica", "james", "jamie", "jane", "january", "japan", "jason", "jasper", "java", "jazz", "jean", "jedi", "jeep",  	// 0x0740 - 0x074f
	"jeff", "jelly", "jelsoft", "jenkin", "jenny", "jens", "jeremy", "jerome", "jerry", "jersey", "jerusalem", "jess", "jets", "jewelry", "jews", "jill",  	// 0x0750 - 0x075f
	"jimmy", "joan", "jobs", "joel", "joey", "johan", "john", "join", "joke", "jonah", "jones", "jordan", "jose", "josh", "journal", "jovi",  	// 0x0760 - 0x076f
	"joyce", "jpeg", "juan", "judge", "judith", "judy", "juice", "julie", "july", "jump", "junction", "june", "jung", "junior", "junk", "jupiter",  	// 0x0770 - 0x077f
	"jury", "just", "juvenile", "kaiser", "kane", "kansas", "kaplan", "kara", "karen", "karl", "karma", "kate", "kathy", "katie", "katrina", "kazaa",  	// 0x0780 - 0x078f
	"kbps", "keen", "keep", "keith", "kelkoo", "kelly", "kenny", "keno", "kenshin", "kent", "kenwood", "kenya", "kept", "kerala", "kern", "kerr",  	// 0x0790 - 0x079f
	"kevin", "keyboard", "keynes", "keys", "keyword", "khan", "kick", "kidney", "kids", "kijiji", "kilometer", "kimble", "kinase", "kind", "king", "kiribati",  	// 0x07a0 - 0x07af
	"kirk", "kiss", "kitchen", "kits", "kitty", "klein", "knee", "knew", "knife", "knight", "knit", "knives", "knock", "know", "knox", "kong",  	// 0x07b0 - 0x07bf
	"konica", "korea", "korn", "kosovo", "kruger", "kurt", "kuwait", "kyle", "kyocera", "kyoto", "kyrgyz", "label", "labor", "labrador", "labs", "lace",  	// 0x07c0 - 0x07cf
	"lack", "lacroix", "ladd", "laden", "lady", "lafayette", "laguna", "lake", "lamb", "lamp", "lance", "land", "lane", "language", "lanka", "lans",  	// 0x07d0 - 0x07df
	"laos", "laptop", "large", "larry", "laser", "last", "late", "latitude", "latter", "latvia", "laude", "laugh", "launch", "laura", "lavender", "lavie",  	// 0x07e0 - 0x07ef
	"lawn", "lawrence", "laws", "lawyer", "layer", "laying", "layout", "lazy", "ldap", "lead", "leaf", "league", "leak", "lean", "leap", "learn",  	// 0x07f0 - 0x07ff
	"least", "leather", "leave", "lebanon", "lecture", "leeds", "left", "legacy", "legend", "lego", "legs", "leica", "leigh", "leisure", "lemma", "lemon",  	// 0x0800 - 0x080f
	"lend", "length", "lens", "leon", "leslie", "lesotho", "less", "lets", "letter", "leukemia", "level", "levi", "levy", "lewis", "lexis", "lexmark",  	// 0x0810 - 0x081f
	"lexus", "liable", "liaison", "libdevel", "liberty", "library", "libs", "libya", "license", "lick", "lieu", "life", "lift", "light", "like", "lily",  	// 0x0820 - 0x082f
	"lima", "lime", "limit", "limo", "lincoln", "linda", "line", "ling", "link", "linux", "lion", "lipid", "lips", "liquid", "lisa", "lisbon",  	// 0x0830 - 0x083f
	"lisp", "list", "lite", "lithium", "little", "live", "lloyd", "load", "loan", "lobby", "locate", "lock", "lodge", "logan", "logged", "login",  	// 0x0840 - 0x084f
	"logo", "logs", "lohan", "london", "lone", "long", "look", "loop", "loose", "lopez", "lord", "lose", "loss", "lost", "lots", "lotto",  	// 0x0850 - 0x085f
	"lotus", "loud", "louis", "lounge", "love", "lower", "lows", "loyalty", "luca", "lucia", "luck", "lucy", "luggage", "luis", "luke", "luna",  	// 0x0860 - 0x086f
	"lunch", "lung", "luther", "luxury", "lycos", "lying", "lynn", "lynx", "lyon", "lyric", "macau", "macdonald", "mace", "machine", "macintosh", "macro",  	// 0x0870 - 0x087f
	"madame", "madden", "made", "madison", "madness", "madonna", "madrid", "madthumbs", "magazine", "maggie", "magic", "magna", "maid", "mail", "main", "majesty",  	// 0x0880 - 0x088f
	"major", "make", "malawi", "malcolm", "malden", "male", "mali", "mall", "malt", "mama", "manage", "mandy", "manga", "manhattan", "mania", "mankind",  	// 0x0890 - 0x089f
	"mann", "manor", "mans", "manual", "many", "maple", "mapped", "mapquest", "maps", "mara", "marble", "march", "mardi", "margin", "maria", "mark",  	// 0x08a0 - 0x08af
	"marla", "marry", "mars", "mart", "marvel", "mary", "mask", "mason", "mass", "master", "match", "material", "math", "matrix", "mats", "matt",  	// 0x08b0 - 0x08bf
	"mature", "maui", "mauro", "maxi", "maxwell", "maya", "maybe", "mayer", "mayo", "mazda", "mbps", "mccain", "mcdonald", "mcgraw", "mead", "meal",  	// 0x08c0 - 0x08cf
	"mean", "measure", "meat", "mechanic", "medal", "media", "medline", "meet", "mega", "melbourne", "melissa", "melon", "member", "memory", "memphis", "mens",  	// 0x08d0 - 0x08df
	"ment", "menu", "mercy", "mere", "merge", "merit", "merry", "mesa", "mesh", "message", "meta", "meter", "metro", "mexico", "meyer", "mgmt",  	// 0x08e0 - 0x08ef
	"mice", "michael", "mick", "micro", "middle", "midi", "midland", "midnight", "midst", "midway", "might", "migrant", "miguel", "mike", "milan", "mild",  	// 0x08f0 - 0x08ff
	"mile", "military", "milk", "mill", "milton", "milwaukee", "mime", "mind", "mine", "mini", "minnesota", "minor", "mins", "mint", "minute", "mira",  	// 0x0900 - 0x090f
	"mirror", "misc", "misled", "misplace", "miss", "mist", "mitigate", "mixed", "mixing", "mixture", "mobile", "mode", "modify", "mods", "module", "moins",  	// 0x0910 - 0x091f
	"moist", "mold", "mole", "moll", "moment", "moms", "mona", "monday", "money", "mongolia", "monica", "monk", "mono", "monroe", "monster", "month",  	// 0x0920 - 0x092f
	"monument", "mood", "moon", "moore", "moose", "more", "morgan", "morning", "morocco", "morris", "mortgage", "mosaic", "moscow", "moses", "moss", "most",  	// 0x0930 - 0x093f
	"motel", "mother", "motion", "motor", "mount", "mouse", "mouth", "movado", "move", "movie", "mozart", "mozilla", "mpeg", "mrna", "msgid", "msgs",  	// 0x0940 - 0x094f
	"msie", "much", "mudvayne", "mugs", "muhammad", "multi", "mumbai", "munich", "murphy", "murray", "muscle", "museum", "music", "must", "mutant", "mutual",  	// 0x0950 - 0x095f
	"muze", "myanmar", "myers", "myrtle", "myself", "mysimon", "myspace", "mysql", "mystic", "myth", "nail", "name", "nano", "napa", "naples", "napoli",  	// 0x0960 - 0x096f
	"naps", "narnia", "narrow", "nasa", "nascar", "nasd", "nash", "natal", "nathan", "nation", "nato", "nature", "naughty", "nauru", "naval", "navigate",  	// 0x0970 - 0x097f
	"navy", "ncaa", "ncbi", "neal", "near", "neat", "nebraska", "necessary", "neck", "nederland", "need", "negative", "neglect", "negotiate", "neighbor", "neil",  	// 0x0980 - 0x098f
	"neither", "nell", "nelson", "neon", "neopets", "nepal", "nero", "nerve", "nest", "netbsd", "netgear", "nets", "network", "neuro", "neutral", "nevada",  	// 0x0990 - 0x099f
	"never", "nevis", "newark", "newbie", "newcomer", "newer", "newly", "newman", "newport", "news", "newton", "next", "ngos", "niagara", "nicaragua", "nice",  	// 0x09a0 - 0x09af
	"niche", "nick", "nico", "night", "nike", "nikki", "nile", "nina", "nine", "ninja", "nintendo", "nirvana", "nissan", "nitro", "nixon", "noaa",  	// 0x09b0 - 0x09bf
	"noah", "nobel", "noble", "nobody", "node", "noise", "nokia", "nominal", "none", "nonlinear", "nonprofit", "nonstop", "noon", "nord", "norfolk", "normal",  	// 0x09c0 - 0x09cf
	"north", "norway", "nose", "notary", "notch", "note", "nothing", "notice", "notorious", "notre", "noun", "nova", "novel", "nowhere", "ntsc", "nuclear",  	// 0x09d0 - 0x09df
	"nudist", "nuke", "null", "number", "numeric", "nurse", "nutrient", "nuts", "nutten", "nvidia", "nylon", "nyse", "oakley", "oaks", "oasis", "obese",  	// 0x09e0 - 0x09ef
	"obituary", "object", "oblique", "obscure", "observe", "obsolete", "obstet", "obtain", "obvious", "occasion", "occur", "ocean", "oclc", "october", "odds", "odor",  	// 0x09f0 - 0x09ff
	"odyssey", "oecd", "offer", "office", "offline", "offs", "often", "ohio", "oils", "okay", "oklahoma", "older", "olds", "olive", "olympic", "omaha",  	// 0x0a00 - 0x0a0f
	"oman", "omega", "omission", "omit", "once", "oncology", "ones", "ongoing", "onion", "online", "only", "onset", "onsite", "ontario", "onto", "oops",  	// 0x0a10 - 0x0a1f
	"open", "opera", "opinion", "oppose", "option", "oracle", "orange", "orbit", "orchid", "order", "ordinary", "oregon", "orient", "origin", "orlando", "orleans",  	// 0x0a20 - 0x0a2f
	"ornate", "orthodox", "oscar", "oslo", "other", "ottawa", "ought", "ounce", "ours", "outback", "outcome", "outdoor", "outer", "outfit", "outgoing", "outlet",  	// 0x0a30 - 0x0a3f
	"output", "outrage", "outside", "oval", "oven", "over", "owen", "owns", "oxford", "oxide", "oxygen", "pace", "pacific", "pack", "padd", "pads",  	// 0x0a40 - 0x0a4f
	"pagan", "page", "pagina", "paid", "pain", "pair", "palau", "pale", "palm", "palo", "pamela", "panama", "panda", "panel", "panic", "panoz",  	// 0x0a50 - 0x0a5f
	"pant", "papa", "paper", "para", "parc", "parent", "paris", "park", "pars", "part", "pasadena", "paso", "pass", "past", "patch", "patent",  	// 0x0a60 - 0x0a6f
	"path", "patio", "patrol", "pattern", "paul", "pause", "pavilion", "paxil", "payable", "payday", "paying", "payment", "payne", "paypal", "payroll", "pays",  	// 0x0a70 - 0x0a7f
	"pcmcia", "pdas", "peace", "peak", "peanut", "pear", "peas", "pedal", "pedestal", "pediatr", "pedro", "peeing", "peel", "peer", "penalty", "pence",  	// 0x0a80 - 0x0a8f
	"pending", "peng", "peninsula", "penn", "pens", "pentax", "people", "pepper", "peptic", "percent", "perfect", "perhaps", "perimeter", "perky", "perl", "permit",  	// 0x0a90 - 0x0a9f
	"perry", "person", "perth", "peru", "peso", "pest", "pete", "petit", "petra", "pets", "peugeot", "pewter", "pgsql", "phantom", "pharmacy", "phase",  	// 0x0aa0 - 0x0aaf
	"phil", "phoenix", "phone", "phosphate", "photo", "phrase", "phys", "piano", "pichunter", "pick", "picnic", "pics", "picture", "piece", "pier", "pigs",  	// 0x0ab0 - 0x0abf
	"pike", "pile", "pill", "pilot", "pine", "ping", "pink", "pinned", "pins", "pioneer", "pipe", "pirate", "pitt", "pixel", "pizza", "place",  	// 0x0ac0 - 0x0acf
	"plain", "plan", "plaque", "plasma", "plate", "play", "plaza", "please", "pledge", "plenty", "plot", "plug", "plum", "plus", "plymouth", "pmid",  	// 0x0ad0 - 0x0adf
	"pocket", "podcast", "poem", "poet", "pogo", "point", "poison", "poker", "polar", "pole", "policy", "poll", "polo", "poly", "pond", "pont",  	// 0x0ae0 - 0x0aef
	"pony", "pooh", "pool", "poor", "pope", "popular", "porch", "pork", "porsche", "port", "pose", "position", "possible", "post", "potato", "potential",  	// 0x0af0 - 0x0aff
	"pots", "potter", "pouch", "poultry", "pound", "pour", "powder", "power", "practice", "prague", "praise", "pray", "precise", "pred", "prefer", "pregnant",  	// 0x0b00 - 0x0b0f
	"prejudice", "prelude", "premium", "prep", "prereq", "press", "pretty", "prev", "pride", "priest", "prime", "print", "prior", "prism", "privacy", "prix",  	// 0x0b10 - 0x0b1f
	"prize", "proactive", "problem", "process", "product", "profit", "program", "prohibit", "project", "prolog", "prom", "pron", "proof", "proper", "protein", "proud",  	// 0x0b20 - 0x0b2f
	"provide", "proxy", "prozac", "pseudo", "psychic", "public", "pubmed", "pubs", "puerto", "puff", "pull", "pulmonary", "pulp", "pulse", "puma", "pump",  	// 0x0b30 - 0x0b3f
	"punch", "punish", "punk", "pupil", "purchase", "purdy", "pure", "puri", "purple", "purse", "push", "puts", "putty", "puzzle", "pyramid", "python",  	// 0x0b40 - 0x0b4f
	"qaeda", "qatar", "quad", "quake", "quality", "quantum", "quartz", "quebec", "queen", "query", "question", "queue", "quick", "quiet", "quilt", "quinn",  	// 0x0b50 - 0x0b5f
	"quit", "quiz", "quote", "race", "rachel", "rack", "radeon", "radio", "rage", "raid", "rail", "rain", "raise", "raleigh", "rally", "ralph",  	// 0x0b60 - 0x0b6f
	"rammed", "ramp", "ranch", "rand", "range", "rank", "rant", "rapid", "rare", "rate", "rather", "ratio", "rats", "rave", "raymond", "rays",  	// 0x0b70 - 0x0b7f
	"razor", "razr", "reach", "read", "reagan", "real", "rear", "reason", "rebate", "rebel", "reboot", "rebuild", "recap", "recent", "recharge", "recipe",  	// 0x0b80 - 0x0b8f
	"record", "recruit", "rect", "recursos", "recycle", "redeem", "redhat", "rediff", "reduce", "reebok", "reed", "reef", "reel", "referred", "refine", "reflect",  	// 0x0b90 - 0x0b9f
	"reform", "refresh", "refund", "regard", "reged", "reggae", "region", "regret", "regular", "rehab", "reid", "reign", "reimburse", "rein", "relate", "release",  	// 0x0ba0 - 0x0baf
	"relief", "reload", "rely", "remain", "remember", "remix", "remote", "renal", "render", "rene", "reno", "rent", "repair", "repec", "reply", "report",  	// 0x0bb0 - 0x0bbf
	"reprint", "republic", "request", "rescue", "reserve", "resin", "resort", "respect", "rest", "result", "retail", "retention", "retire", "retreat", "return", "reunion",  	// 0x0bc0 - 0x0bcf
	"reuse", "reuter", "reveal", "review", "revolve", "reward", "reynolds", "rfid", "rhapsody", "rhode", "rhythm", "ribbon", "rica", "rice", "rich", "rick",  	// 0x0bd0 - 0x0bdf
	"rico", "ride", "ridge", "rifle", "right", "rigid", "rigorous", "riley", "ring", "ripe", "ripper", "rise", "risk", "rita", "ritual", "riva",  	// 0x0be0 - 0x0bef
	"river", "riviera", "road", "robb", "robert", "robin", "robot", "robust", "roche", "rock", "rode", "rodney", "rodrigo", "rods", "roget", "rogue",  	// 0x0bf0 - 0x0bff
	"roland", "role", "roll", "roma", "rome", "roms", "ronald", "roof", "rook", "room", "roos", "root", "rope", "rosa", "rose", "ross",  	// 0x0c00 - 0x0c0f
	"roster", "rotary", "roth", "rotten", "rough", "roulette", "round", "route", "rows", "royal", "rubber", "ruby", "rude", "rugby", "rugged", "rugs",  	// 0x0c10 - 0x0c1f
	"rule", "rumor", "running", "runs", "runtime", "rush", "russia", "rust", "ruth", "rwanda", "ryan", "saab", "sacred", "saddam", "sadly", "safari",  	// 0x0c20 - 0x0c2f
	"safe", "saga", "sage", "sahara", "said", "sail", "saint", "sake", "salad", "sale", "salim", "sally", "salmon", "salon", "salt", "salvage",  	// 0x0c30 - 0x0c3f
	"samba", "same", "samoa", "sample", "samsung", "samui", "sanchez", "sand", "sang", "sanity", "sans", "santa", "sanyo", "sapporo", "sara", "saskatoon",  	// 0x0c40 - 0x0c4f
	"sata", "satellite", "satin", "saturday", "sauce", "saudi", "sauna", "savage", "save", "saying", "says", "sbjct", "scale", "scam", "scan", "scar",  	// 0x0c50 - 0x0c5f
	"scene", "scheme", "schmid", "schneider", "school", "schwab", "science", "scoop", "scope", "score", "scott", "scout", "scrap", "screw", "script", "scroll",  	// 0x0c60 - 0x0c6f
	"scrub", "scsi", "scuba", "scully", "sdram", "seafood", "seagate", "seal", "seam", "sean", "search", "season", "seat", "sebastian", "second", "secret",  	// 0x0c70 - 0x0c7f
	"sector", "secure", "sedan", "sediment", "seed", "seeing", "seek", "seem", "seen", "sees", "sega", "segment", "seize", "select", "self", "sell",  	// 0x0c80 - 0x0c8f
	"semantic", "semester", "semi", "senate", "send", "seneca", "senior", "sensor", "sent", "separate", "september", "sequence", "serb", "series", "serum", "server",  	// 0x0c90 - 0x0c9f
	"seth", "sets", "settle", "setup", "seven", "sewage", "sewer", "sewing", "sexcam", "sexo", "sexy", "shade", "shaft", "shake", "shall", "sham",  	// 0x0ca0 - 0x0caf
	"shan", "shape", "share", "shaw", "shed", "sheet", "sheffield", "shelf", "shemale", "shepard", "sheri", "shield", "shift", "shin", "ship", "shirt",  	// 0x0cb0 - 0x0cbf
	"shock", "shoe", "shop", "short", "shot", "should", "show", "shri", "shuffle", "shut", "side", "sidney", "siemens", "sierra", "sigh", "sigma",  	// 0x0cc0 - 0x0ccf
	"sign", "silent", "silica", "silk", "sill", "silver", "similar", "simmons", "simon", "simple", "sims", "simulate", "since", "single", "sink", "sins",  	// 0x0cd0 - 0x0cdf
	"sioux", "sister", "site", "sits", "sitting", "situated", "sixth", "size", "skate", "skelton", "sketch", "skiing", "skin", "skip", "skirt", "skull",  	// 0x0ce0 - 0x0cef
	"skype", "slam", "slate", "sleep", "slice", "slide", "slight", "slim", "slip", "slope", "slot", "slovak", "slow", "small", "smart", "smell",  	// 0x0cf0 - 0x0cff
	"smile", "smith", "smoke", "smooth", "smtp", "smug", "snack", "snake", "snap", "snmp", "snow", "soap", "soccer", "social", "sock", "soda",  	// 0x0d00 - 0x0d0f
	"sodium", "sofa", "software", "soil", "solar", "sold", "sole", "solid", "solo", "solution", "solve", "soma", "some", "song", "sonic", "sons",  	// 0x0d10 - 0x0d1f
	"sony", "soon", "sophie", "sorry", "sort", "sought", "soul", "sound", "soup", "source", "south", "sovereign", "space", "spain", "spam", "span",  	// 0x0d20 - 0x0d2f
	"spare", "spas", "spatial", "speak", "special", "speed", "spell", "spent", "sphere", "spider", "spill", "spin", "spirit", "splash", "split", "spoke",  	// 0x0d30 - 0x0d3f
	"sponsor", "sport", "spot", "spouse", "spray", "spread", "spring", "spyware", "squad", "squid", "stable", "stack", "stad", "staff", "stage", "stain",  	// 0x0d40 - 0x0d4f
	"stake", "stamp", "stand", "staple", "star", "state", "stay", "steam", "steel", "stefan", "stein", "stem", "step", "stern", "steve", "stew",  	// 0x0d50 - 0x0d5f
	"stick", "stiff", "still", "stimuli", "stir", "stock", "stole", "stomp", "stone", "stood", "stop", "store", "stove", "strap", "street", "strip",  	// 0x0d60 - 0x0d6f
	"strong", "struct", "stuart", "stuck", "study", "stuff", "stun", "style", "subaru", "subclass", "subd", "subject", "sublime", "submit", "subscribe", "subtle",  	// 0x0d70 - 0x0d7f
	"suburb", "subway", "succeed", "such", "sudan", "sudden", "sued", "suffer", "sugar", "suggest", "suit", "sullivan", "summer", "sunday", "sunlight", "sunny",  	// 0x0d80 - 0x0d8f
	"sunrise", "suns", "super", "supply", "supra", "sure", "surf", "surge", "suriname", "surname", "surplus", "surrey", "survey", "suse", "suspect", "sustain",  	// 0x0d90 - 0x0d9f
	"sutton", "suzanne", "suzuki", "swan", "swap", "swaziland", "sweat", "sweden", "sweet", "swift", "swim", "swing", "switches", "swivel", "sword", "sydney",  	// 0x0da0 - 0x0daf
	"syllabi", "symantec", "symbol", "symmetry", "symptom", "sync", "syndrome", "synod", "synth", "syracuse", "syria", "system", "table", "tabs", "tack", "taco",  	// 0x0db0 - 0x0dbf
	"tact", "tagged", "tags", "tahoe", "tail", "taipei", "taiwan", "take", "tale", "talk", "tall", "tami", "tampa", "tank", "tanned", "tanzania",  	// 0x0dc0 - 0x0dcf
	"tape", "tara", "target", "tariff", "task", "tasman", "taste", "tattoo", "taught", "taxa", "taxes", "taxi", "taxon", "taxpayer", "taylor", "teach",  	// 0x0dd0 - 0x0ddf
	"team", "tear", "tech", "teddy", "teen", "tees", "telecom", "tell", "telnet", "temp", "tenant", "tend", "tennis", "tens", "tent", "tenure",  	// 0x0de0 - 0x0def
	"teresa", "term", "terry", "tesco", "test", "texas", "text", "thai", "tham", "than", "that", "theatre", "thee", "theft", "thehun", "their",  	// 0x0df0 - 0x0dff
	"them", "then", "theory", "there", "these", "they", "thick", "think", "third", "this", "thomas", "thong", "thor", "those", "thou", "three",  	// 0x0e00 - 0x0e0f
	"thrice", "through", "thru", "thumb", "thunder", "thursday", "thus", "thyroid", "tibetan", "ticket", "tide", "tied", "tier", "ties", "tiff", "tiger",  	// 0x0e10 - 0x0e1f
	"tight", "tile", "till", "tilt", "timber", "time", "timor", "tina", "tiny", "tion", "tips", "tire", "tissue", "titan", "title", "tivo",  	// 0x0e20 - 0x0e2f
	"tobago", "today", "todd", "todo", "toes", "together", "togo", "token", "tokyo", "told", "toledo", "toll", "tomas", "tomb", "tome", "tommy",  	// 0x0e30 - 0x0e3f
	"tomorrow", "tone", "tong", "toni", "tons", "tony", "took", "tool", "topic", "topless", "tops", "torch", "torn", "toronto", "torque", "torre",  	// 0x0e40 - 0x0e4f
	"toshiba", "total", "tote", "touch", "tough", "tour", "toward", "tower", "town", "toxic", "toyota", "toys", "track", "trade", "traffic", "tragic",  	// 0x0e50 - 0x0e5f
	"train", "tram", "trans", "trap", "trash", "trauma", "travel", "tray", "treat", "tree", "trek", "trembl", "trend", "treo", "trevor", "trial",  	// 0x0e60 - 0x0e6f
	"tribe", "trick", "tried", "trilogy", "trim", "trina", "trio", "trip", "trium", "trivia", "troop", "trophy", "trouble", "troy", "truck", "true",  	// 0x0e70 - 0x0e7f
	"truly", "truman", "trunk", "trust", "truth", "trying", "tsunami", "tube", "tuck", "tucson", "tuesday", "tuition", "tulsa", "tumor", "tune", "tung",  	// 0x0e80 - 0x0e8f
	"tunnel", "turbo", "turks", "turn", "turquoise", "turtle", "tuscan", "tutor", "tuvalu", "twain", "twelve", "twenty", "twice", "twiki", "twill", "twin",  	// 0x0e90 - 0x0e9f
	"twist", "tyler", "type", "ucla", "uganda", "ugly", "ukraine", "ultimate", "ultra", "umbro", "unable", "unanimous", "unaudited", "unbiased", "uncanny", "uncertain",  	// 0x0ea0 - 0x0eaf
	"uncheck", "uncle", "under", "undo", "unesco", "unfair", "unicef", "uniform", "union", "uniprotkb", "unique", "unit", "universal", "unix", "unknown", "unlawful",  	// 0x0eb0 - 0x0ebf
	"unless", "unlike", "unlock", "unproven", "unreal", "unset", "unsigned", "unspoken", "unstable", "until", "unto", "unused", "unwanted", "unwrap", "upcoming", "update",  	// 0x0ec0 - 0x0ecf
	"upgrade", "upload", "upon", "upper", "upright", "upset", "upstate", "upward", "uranium", "urban", "urge", "urls", "usable", "usage", "usda", "used",  	// 0x0ed0 - 0x0edf
	"useful", "useless", "usenet", "user", "uses", "usgs", "usher", "using", "usps", "usually", "utah", "util", "vacation", "vaccine", "vacuum", "vaio",  	// 0x0ee0 - 0x0eef
	"vale", "valid", "valley", "value", "valve", "vampire", "vancouver", "vanguard", "vanity", "vans", "vanuatu", "vapor", "various", "vary", "vascular", "vase",  	// 0x0ef0 - 0x0eff
	"vast", "vault", "vbulletin", "vectra", "vegas", "vegetable", "vehicle", "velocity", "velvet", "vendor", "veneer", "venice", "vent", "venue", "vera", "verb",  	// 0x0f00 - 0x0f0f
	"verde", "verify", "verlag", "vermont", "verne", "version", "vertex", "very", "vessel", "vest", "veteran", "viable", "viagra", "vice", "vicious", "vicodin",  	// 0x0f10 - 0x0f1f
	"victim", "video", "vids", "vienna", "viet", "view", "viii", "viking", "villa", "vince", "vine", "vintage", "vinyl", "viola", "viral", "virtual",  	// 0x0f20 - 0x0f2f
	"virus", "visa", "visit", "vista", "visual", "vita", "vitro", "vivo", "vocal", "vodafone", "voice", "void", "voip", "volatile", "volt", "volume",  	// 0x0f30 - 0x0f3f
	"vonage", "vote", "voucher", "voyage", "voyeur", "voyuer", "vsnet", "vuitton", "wade", "wage", "wagon", "waist", "wait", "waive", "wake", "wales",  	// 0x0f40 - 0x0f4f
	"walk", "wall", "walnut", "walsh", "walt", "wang", "wanna", "want", "warcraft", "ward", "ware", "warfare", "warm", "warner", "warren", "wars",  	// 0x0f50 - 0x0f5f
	"warwick", "waste", "watch", "water", "watson", "watt", "wave", "wayne", "ways", "weak", "wealthy", "weapon", "wear", "weather", "weave", "webb",  	// 0x0f60 - 0x0f6f
	"webct", "weber", "weblog", "webmd", "webpage", "webring", "website", "wedding", "wednesday", "weed", "week", "weezer", "weight", "weir", "welcome", "well",  	// 0x0f70 - 0x0f7f
	"welsh", "wendy", "went", "were", "wesley", "west", "wetland", "whale", "what", "wheat", "wheel", "when", "where", "whether", "which", "while",  	// 0x0f80 - 0x0f8f
	"whirl", "whoever", "whois", "wholly", "whom", "whose", "wichita", "wick", "wide", "widget", "widow", "width", "wife", "wifi", "wiki", "wild",  	// 0x0f90 - 0x0f9f
	"wiley", "will", "wilma", "wilson", "winch", "wind", "wine", "wing", "winnt", "wins", "winter", "winxp", "wire", "wisconsin", "wisdom", "wise",  	// 0x0fa0 - 0x0faf
	"wish", "with", "witness", "wives", "wizard", "wolf", "wolves", "woman", "women", "wonder", "wong", "wont", "wood", "wool", "worcester", "word",  	// 0x0fb0 - 0x0fbf
	"wore", "work", "world", "worm", "worn", "worry", "worst", "worth", "would", "wound", "woven", "wrap", "wrestle", "wretch", "wright", "wrist",  	// 0x0fc0 - 0x0fcf
	"write", "wrong", "wrote", "wyoming", "xbox", "xenical", "xhtml", "xlib", "xmas", "xnxx", "yacht", "yahoo", "yale", "yamaha", "yang", "yard",  	// 0x0fd0 - 0x0fdf
	"yarn", "yeah", "year", "yeas", "yellow", "yemen", "yesterday", "yield", "yoga", "york", "young", "your", "youth", "yukon", "zambia", "zdnet",  	// 0x0fe0 - 0x0fef
	"zealand", "zeppelin", "zero", "zhang", "zimbabwe", "zinc", "zodiac", "zoloft", "zombie", "zone", "zoofilia", "zoom", "zoophilia", "zope", "zshops", "zurich"  	// 0x0ff0 - 0x0fff
};

} // namespace _details

bool MnemonicEncode(LPCVOID data, UINT size, rt::String& out)
{
	out.Empty();
	if(size)
	{
		UINT size_work = size;
		if(size_work%4)
		{
			size_work = (size + 3)/4*4;
			LPVOID p = _Alloca32AL(size_work);
			memcpy(p, data, size_work);
			memset((LPBYTE)p + size, 0, size_work - size);
			data = p;
		}

		rt::BooleanArrayRef bits;
		bits.Init(data, size_work*8);

		for(UINT i=0; i<size*8; i+=_details::MnemonicBitBlock)
			out += _details::g_MnemonicDict[bits.Get(i, _details::MnemonicBitBlock)] + ' ';

		out.TrimRight(1);
	}

	return true;
}

bool MnemonicDecode(const rt::String_Ref& code, LPVOID data, UINT size)
{
	if(code.IsEmpty() && size == 0)
		return true;

	static const rt::CharacterSet sep(" \t\r\n");

	rt::BooleanArray<> bits;
	bits.SetBitSize(size*8 + _details::MnemonicBitBlock);
	bits.ResetAll();

	rt::String_Ref word;
	UINT bit_co = 0;
	while(bit_co < size*8)
	{
		if(!code.GetNextToken(word, sep))
			return false;

		auto* p = std::lower_bound(&_details::g_MnemonicDict[0], &_details::g_MnemonicDict[_details::MnemonicDictSize], word);
		if(*p != word)return false;

		uint32_t c = (uint32_t)(p - &_details::g_MnemonicDict[0]);
		bits.Set(bit_co, (DWORD)c, _details::MnemonicBitBlock);
		bit_co += _details::MnemonicBitBlock;
	}

	memcpy(data, bits.GetBits(), size);
	return true;
}

uint32_t MnemonicAutoComplete(const rt::String_Ref& prefix, rt::String_Ref* out, UINT out_size)
{
	auto* p = std::lower_bound(&_details::g_MnemonicDict[0], &_details::g_MnemonicDict[_details::MnemonicDictSize], prefix);
	uint32_t i = 0;
	for(; i<out_size && p && p->StartsWith(prefix); i++, p++, out++)
		*out = *p;

	return i;
}

} // namespace upw