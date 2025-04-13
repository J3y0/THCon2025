from Crypto.Cipher import AES
import hashlib
from pwn import xor

BLOCK_SIZE = 16
SALT = b"THCON2025"
ARCH = 64
KEYS = [(b'K;~\x99\xc0D\xfd\xcf\xc9\x8b\xa8\xe9o\xf8\x9d\x9c', b'\xbc\xd9ip\xfa\x9b\x1c\xe1\xaaP\x1a]\x89M\xcf\xec'), (b'\xcb\xae%\x8e/z\xe0\x82\xf2-\x97U\xae\xf4>\x8c', b'\xc2fqKG1\x80z\xd1qs\xd8\xbfF\xef\x9d'), (b'\xd2\xb2\xae\n\t\xc7\xac\xe7\xb3Ys\xa6,\xd9\xce\xb4', b'\xd0\x8dZ\xa3\x07\xb2\xc3X\xe5\xf6/\xa9\xcdm\xb0n'), (b'\xf6\xda\xfe\xbdU!,~QX.\x99\xee0\x1cn', b"\xb6\xc6Z\xd5\n\xad\x84\x89\x80r?\x12\xc1\xe1S'"), (b'\xdb\xfe\xc7\x8cp\x90\xda\xf3[g)\xab\xd7\x11\xfe<', b'.T\x06\x89<\x80\xce\xd1\xbc\xe6DS\x1e\xb8\xc9+'), (b'\xfb\xd9D\x80:\x0e\xd3\x1eh\xc6\x00\xc9\xfa\xb6\xb3\x08', b':\x01{7k\x1c\x9en<\x90w\xa0\xba\n\x8c\xa1'), (b'\xc8\x91\x123\x7f\xadH2\x10\x91q\xce)C7\x0c', b'c\xc6\x88\x132\xd1\xfa\xd4\x05.\xa6W\x08\x05\x9e\x05'), (b'\xcbx\xf6\x83S\xf1\xb8\xba\x86\xf9d%9\xd6\xb9\xc9', b'\xe5\xf8\xb1\xd6\x08M\x84~\x0b2\x995\xaf\x9b9\x98'), (b'\x974\x1fq\xb1\xdb\xea!\xb2\xf9\xd3\x0c\x98\x85l-', b'\xaf\x0c\x8f\x85\x85\x7f\xadeyw\xb2a\xa1\x00jV'), (b'\x81r7H\xed\x07X\xbc\xeb\x9bK\x81\x97b\xd6\xcb', b'E\x16\xe6\t-C[`d\xa45\xa4\x96r\xcd\xf9'), (b'\xd9\xaf\xca;\xa6=\xee\x17\xb56d?\xf5\xbc?#', b'\xf9&\x12\xb5S\xefl\x8a\xa0\xcf\x14j"\xb4A\xdb'), (b',/bGXX\x99\x8d\xdaZ\x07\xd7`d\xc3\x86', b'\xc9\xa9\xe4\x8f\x80u)\xde\xe4kQ\x88q\xe6XN'), (b'fn\xe9`\xed\x89w\x85X\x1f\x0ej\x0f\x93\xacP', b'\x84\x8aBzC\xf4\xfeb\xb8\x95C\xea\xdc6?\x83'), (b'j-G\xce\xc6\xf3\x0e\xc1\x03\xb8\x87\xfa\x18\x02\x1e7', b'\xec\x977\x86\xc8\xb3\xd4k\xbbR\xadV:\x13\xdd\xc0'), (b'\xdfY\x1e\x02\x90\xaa\x16|\x1d\xb2\x0f.\xeb\xdayt', b'E\xf0\xa0}\x1e\xeeB-"\xb1\xf5\xe65\xb0\xa0\xb7'), (b'\xc2\xc4i5\xe3\x06 \xf0\x89\xcc\xae\x9a\xce>Z\x8f', b"'N!\xc6U\x9a\x9fk\n$\xe6\xc7\xdc\x94\xd6`"), (b'\x98\xec\xcc\xf8\xe6\xcc\x89VH\x9e\xdf\xf5\xc1&\xf1#', b'1\xd5`\x10\xb3\x1e\xd5\xf9\x9eP\x83\xb6\x80dr\xdd'), (b'g;[\xcdu\xb6\xfd*sp\x96G\xd8hP\x97', b'1a\xadCz\x88\xed\x1c\xb0E\x14\xb4\xc9\x15?r'), (b'D3\x10\xf9:\x83fb\xf4E\xf21\xd7\xacD\x97', b'B\x1c0\x94\xf68\xd9\x80?\x0c\x1b\xd2\x98\xe1(d'), (b'\x94+\x8e\x8d5\x05kiF\x9f\x9f[\x89o4\xd1', b'X;GP\xe5\xb4s\xf4\xf0\x85J\x96\xf9\xe7\xc1\xdc'), (b'4\xa8\xbe}U\t\x8f\x16\xe4v\xfc\x18g\xf1\xb1\xb3', b'-\x17u\xc6\x10v`\x84\xb2\x0b\xaa\xee?\xb3\x97\xe1'), (b'\xb4%uU\x8a\x9a\xb9\x07\x92\x96@\xc7\xe4\x95\x05W', b'\x00\xd1m\xe9fYF\x99\x8fE>+\xa7kr\xcc'), (b'w\x9b(\xb9En\xc9Cd\t3p\xd7\xb3\x17\xaf', b'=\x14\x94\n;9Yx:\xd6.\xcc\x9bp\xaf\x84'), (b'\xe1hhB8sw\xe2e\xc7\x7ft*\x1e\xbdM', b'nV\xe6\xd6\xdds\xbb\xc36\tUY1\xab\xfb\x91'), (b'@\xa4o\xc7m\xc3\x18\xc7xw\xfeEQu\xfd\xeb', b'H\xbd\xf5\xcdUhC\xb1\xd5\x94\x96r2\xef\xcd\xbe'), (b']\xcf\xb7\xee\xc7\xabW\x02\x89\xc2\xb5zY~P\xe6', b'5(\x1a\xb98>v\xd3\x83\x11R\x0e8~\x8b\xcf'), (b"MV\rj\x80\xcb'\x10\x85\x1d\xd5u\x8e\xb1Gz", b'\x9e\x00\xaa\xf7\x00\xdf\xa4\xe9\xbd\\\xf7\x17\xc8\x97^4'), (b'+\xeaR\x08\x9d$\xcd\xa1\x88\xa5\xd9/D6{\xf4', b'y1\x1d\xb8\xf60\xd5\x02=$\n\x90h\x8e:r'), (b'\xd6\x16P\xe0%\x8b"\xd5vJ\xb9\x0fL\xd6\xce\xa4', b'*\xda\xea\xbap\x9c\xe1\x8f\xe9\xb6\xa8\xcd\x0f\x90\xff\x0e'), (b'\x05\x83\x16c\x0b\xe5\x9c\xd0\x0fg\xd8*\xb1,\xcb\x0e', b'\x8c\xe5\xb3\xcecm\x10\xc1:\x06\xf9\xb1mx,e'), (b'"\xa3w\x84\xdfx\xa7\xa0Uv\xa3?$V;*', b';>\x9f6aA\rV\xf0\xfe\x0f\x831\x8cg.'), (b'_\xcf\x9b\xf4\x8e\xfcB\xe1DX!\xc7\x91\x15r\xc0', b'An~\x0b\x16\xd1\x90\xb8@t?D\xf4\xd5:\xba'), (b'\xdaj\xe4\xbe\xb6\x1ba\x81\x9dn\xd6\x89\x97V65', b'\xe7l\x00\xa2+\x0ek8CDj\x1bw\x16\xc6\x0c'), (b'\x1f#Q\xc1\xba\xdf\x8d\xa8}G\xaadj\xc3\xb0\xc2', b'\x06\xb8\xb3j\xcb>&\xd8@\x80\x9cQ\x89h&\xa2'), (b'\xb8\xe2\xd0\xce\x88\x1b,\n8\x96IrP\xbbL\xad', b'\xc6\xa5g9\xa1\x84\x9b\xc8\x82 jU\xac\xf9ks'), (b'G\xac\xfei-\xf9\xe36\xb0\x90}\x03R\xda\x81\xe1', b'{\xba]o\xf2L\xd3\x9e\xf0\xe0\xfb{\xda\xf2\xe4\xf6'), (b'\xce\x1f\r\x87\x8d\xfe\x94\x93\x93\x9fd\xfbg\xbf\xc0u', b'\xbb\\\xe3\xbehvZ\x81\xfa\x14\xd8\xb9\xf9\x90\xf9Y'), (b'\x80\xda\xfe4\xeag\xb7\xb7iV}\xa3p\xa1\x8a\xd2', b'\x07\x98y\x93b\x0cw\xe3\xcd\xc6\xf0\x01\x83\x8ag\xdb'), (b'\xe8B\x01\x13\x85$\x07\xd2vH\xaaP\xfc\x91(A', b'\xa9\xd3\x9f\x92\xa5\x17W\xfb\x90\xb5\xdeP\xf3\x03\xb8{'), (b"^\x0f\xd0'\xd1\xa8\xce{\xc0\xe6\x07\xf1\xdcg&\xf9", b'B\xef\x0e^\xc5\x08\xea\xc8\xfe\xd1$\xbe\x9e\xf3P='), (b'Z\xdb\x07\xb6\xa9]\xf0\xa97GP`:\x10\x91\xf4', b'M\x03=\xe2\x9f\x98\xe3)\xed6v^:\xb0<\xbd'), (b'\x06\xb9\xf5\x847\\\xac\xe9</w\x86a[\xa7\xff', b'Jf,6f.\xf6\xbe}g$\x8dYQ\xc5A'), (b'\x7fLQ\x83?["\x15\x15S`Ds\xf0\\\x0b', b'\xfd\xc4\x05y1;\xb2jH\xffZ3\x88\xf0\xd9}'), (b'\xc9\xbej\x9d=\xb9\xb9lz\xf6|\xc6\xd5\xd0\xd9/', b'\xd2\x97\x88\x0b\xb5l#\x83\x080\x86\x03\xdf]\xa3Z'), (b'n.\xdaI\x86\xcc~\r\x12\xe4\x108\xf0\xe2j\x8b', b'C\xc5\xbf0i\x8c\xffY\x9d\x16\xd7\xa78\x87\xf4\x1d'), (b'$\xac\x177k\xb4\xd4\x9dk\xf2\xf9{\xa1\x15\xd8o', b"'\x9c\xea7K\xe3\x07\x87\x81\x90\xf8\x16\x86\x8c\x9fH"), (b'8s\x8d\xf6:\xf7\xf3m\xb1\x91\x19\x9e\xef\xc6\x0bT', b'\xd2\x16i$\xb7\x84,="\xc8\x95\xc0voK\x0c'), (b'}\xfe-,\x8a\xb8\xd0\xc2\xb5&\xba\xd8z\xf2`\x83', b'\xbe\xf5k\x82\x18\xdcJ\x90T\x1ai\x16u\xf8\x87@'), (b'\xfe\xb7\x97\xae\\\x87\xd5\x1c\xddw\xc4s\xf9\x05OP', b'\xaau\x15\xd5\xc8\xc4\x01"\xd9\x06\xfd\x7f\xb2[\x06\xe8'), (b'\x99\x84n\x17\x85[\xac1\xdeh\xf3\x0f\x1bO\xd3\x02', b'*0Q\x08\xfa\x10\xc6v\xd3&\xad"|\xd9\xe2\xbd'), (b'\xcfH2\xfc\xdb\x0bV\xca\xb3\x1cTM\xa5@Eg', b'\x9c,\x12\xca\x11y\x05:\x06V\x0b0ZQ+ '), (b'\xa8\xbeF\xe7\x18\xb2\x19\x02\xd7\xdf\xd1\xac\x14\xb7\xd0t', b'\xfb\xfa\xcc\xedi\x8a\xf8\xf9\xaaI\xda\xc9\xba\xc9\x0bq'), (b'\x00\xb57\xf6j9\x928\x1e\xe3Z\x9f\x1f\x85\xe0\xe2', b'I\xb2S\xa3Y\xa3\xd9=Q\x89\xff\xf4Zb\xed\xf2'), (b'\xcd\x90\xd0}u \xfb<\xa2\xb9e(\xf3\xd5o\xf8', b'\x89t\x84\xe7z1%\xc7\xda\x8eKY\xfe\xc1\xc7\xa5'), (b'\rh/\xb7u\x10\xc5\n\xea\xfe\xbe\xb6\xd7\xa9\xd6a', b'\x17\x97\x8a9\xfa\xac:\xb1\r&\x06\x96\xf2T\xc9\xf4'), (b'\xcfn\xac\xfd\x11\x1b\xd0\x04S\xa9\xfe|egJe', b'Ws\x99\x181OF\x11@\xd9\xe5\xddp\xd1A\xd7'), (b'\x12\x16b\x90\xafC\xa2q\x18n\x82\xd5J\xe2Y\xcc', b'\x1e\x06r\x96\xfd;\x87\xf2\x1c\x9a\t\x0b\xbb\n\xc2\xb1'), (b'\xc0\xc7\xf0E\xd1\xf2\xa4\xe1\xdf\x07\xb7\xe1@#\x0e\xca', b'o\xca\xceq`\x04\\&\x1bq\x19\x1a\x8a\xbb\x15\x1d'), (b's\xf0\xc1\xe3\x1cV\x05W\xb3S\x1e_U\x0f\r\xd3', b'j(\x9d\xe6&~9\xa7#\xc8\xab\x84(a\x1f\xbe'), (b'\x07G\tjO\xc5-_\xd6\xd7\x01\x0f.\xb9\xdc\xc0', b'U\x86vsk\xbf\x8f71\x97l\x82\x14\x80\x81C'), (b'*s`ql\xd5\x84{\xb8Jw:\xcd;\x91\xb7', b'\xd2_<\xf8\xff\x10\x08\xd61\xd1\xee>h\xa7\x13\xee'), (b'/\x02\xa8@\x1e\xab\xb1\xa5\x95R\xb3\x1ad\xf1\xac`', b'nd\x91d;\xf0\x95\x97\xa48%P\xc6\xd6I\xf4'), (b'w\x9f7o7C\x92\xc3\x1f"b\xa3\x12oM\xe4', b'\xea\xc1\xc6\x0c\x97\x81\x94\xb2j+\x117A\xb0\xee '), (b'\xa3\x08_;_\xfe\x91Ji7\xd1\xf9\x01/\x84\xec', b'\x98\xe1\xec\xe8\t\xaew}\x1f\xb2L2\x1f%;Z'), (b'\x04;\xa8\x0f\x0b5\xce\x81E\xe59J\xb7TI&', b'\xda\xf1\xff\xf2s\xa2\x0fC\x0b\xaf\xa1\xca\xab\xf4\xd9\xd3'), (
    b'\x831h\xc1\xc8H\xe7\x87\x03\x83zf\xab\x9a<\x12', b'n\x15\xc7$\xe1\xdf\x9dG\xb9j\xd0\t.\xddl%'), (b'ohT\x1c-Sn\x0b\\I`\xe8<c=\xec', b'\xed\x83\xb8\xf1\x86+ \xb5\xfd:\x89~\xd5\xb8\x1e\x13'), (b'\xf4y:i\x99\x02\x87\x86\xad\xd8\xeb\x198\xdf\xcd\x8c', b'-\xf0Z\xb2\x8f\xa1r\xcc\xed\xeb\xeac=\x17\xdd\xa1'), (b'\xd3\x90\xf8o\x07\xf6-\x98\xaf\x1b\x1e8\x11Wk\xc4', b'm)S\xb2|0\xfe},\xec\x04\x95\x86J/*'), (b'\x826\xc0\x85L\xa4\xf9\xd0\xef\xcabClY\x14\xa3', b'\x9b\xd0\x19\x92fV\x1b\xb2\xb8\x1d\x1d\x9a\xd4\xd6\x8d`'), (b'^a\xda\xc5H\xf4}\xb9FU`t\x7f\xfb\xb3&', b'\x84`xgj\xef\x15u\x95l\xf0W\xfa=|\xdd'), (b'u\x95\xac\x9c\x98 K\xafP\\l\x9c\xfc"\xc5\x10', b'\xcb\t\xbe\x8e\x0bZ\x9c\xae\xba\xe6\x9c\xde\xd8U\x01g'), (b'Q4\xbf\xc9\xce\x19\x85\xe0\xae\xdc\xc2y\xd05\xf4l', b'\xb0\xbe\x9d\x82\x03N\x18,\x99\xc0\x0b\xa6\xc7\xb3d\xc7'), (b"itC\xe2\xff\xe0\xd5\x93\x8c\xabw\x1e\xbe'\xb0O", b'\xd5\xf0@l\x08\xd7:vA\xc1\x99\xa6\x16\x0e~\x9e'), (b'B\xd2vQ\xa3\xb6Tt\x91fz\xf7&~\x9c\xfa', b'}\x0eUA\xf0n\xbdW\xacu6\xecx"\xde\xfa'), (b'\x9d\xe6\xbe)_\x95\xe0\xd3>\xdfl\x07C{\x9c]', b'\x14o\xb0\t}:\xb5\x8a#m \xc8@s:\t'), (b'\x03\x98!`{<MO\xc1\xa8\xbaJ\xd3\xb0\xe8\xb3', b"\x94FX\xd3rxe'|\xbe\xa8\x81[wwY"), (b'\xf4\xa6:&\x0c\t\xda\x12\x95\x03\xb6\xedTj[#', b'\xf6K2\x85jM\xech\xb481\x87.Ti\xb6'), (b'K\xf5}\xb9g%9l\xe9\xb0\x01\xb0\x83\xc1O\xf4', b'\xe54\xd5Db\x8c\xef0\xda\xcd\xce\r\x8dK\xf5['), (b'\x99T\n.\xea(\xb0\xf8\xab{\xac\x05\xf2\xc04\xb5', b'O%\xad2\xfd\xf3\xc6\x83\xa1y\x8eI\x11d\xb0R'), (b'\xff\xd0d\x8c\xc3\xfe"SU\xb3\x89\xe5<W\xecg', b"\x94\xfb\x06\xcc\x1c\x00\x0e\x0cWt'\x7f\xb8{\xa3;"), (b'\xae\xb3\xb8\xd5\xe2]!\x1d)*\xf1d6\xa7\xfd\xa5', b'\xee4C\x93\xfe\xcc,\xc3T\xd8\xfe\xde\xfa\x17\xbaf'), (b'\xda\xb1\x8cO\x94\x9av\xd7\x17\t\x95\x0e\x06\xa5\xfa\xdd', b'\x97D\xd3\xf6\xfc\xb4=\x9f\x1cL#w\xd6u}\xf6'), (b'\xb7\x887\xe0uk\xb6k\xd6e\xd2\xda\xd0?=\x11', b'f\x81\xb1\xf3\xcf\x94\xe8\x0esr\xa0%\xf7\x88$\x9d'), (b'`\xb3\xfc\x93\x8c#\xcc\xf7\x02m\xc3\x82\xe5D\xbe_', b'6\xf3\xf9*v<\xe2\x0f\xd4\x11\xd8\xb8L\x17VU'), (b'\xff\xceS\xb9\xe6,y3\x90:\xe4;\xfaE\x8a\x16', b'\x1b\xfc\xde^\x1e\xefh\xd9\xf9c\x8f\xc7\tQ\xf7\x9d'), (b'\xe0\xed\xee1^A$\xfd\x16\xcb\xe1\x81\xc8*\xb5\x16', b'\xaa:%\x9b\xac#H\xd4\xb2O\xe4I\xecX\xb84'), (b'\x8b`{\xff\xb5r\x80({\xa1\xb3(h\x9e\xe8F', b'\xc4\xcbQ5jG!\xb6)\x1e\t\xa0\x07\xb6kS'), (b'\xf1[xU+\xc9\xdd\xec\xd7`\xfa\x9a\xd3\xca\xd9\xe1', b'\xe96\'\xfb\x8c\x93\xcb\x04K\xefm\x12G\x9e\xa5"'), (b'\xaa5\x04\xd6o&\xa3\xae\xf1_\xd6W\xc2\x7f|\x93', b'\x8a%\xf5\x19\xc0o"\xd9\xe4\x1dF\x0bv,o\xa9'), (b'\x04\xc0/\xe3\xf3L\xce\xd9\x0b\xce6\xbd\xf01$\xbc', b'\x19\xeb\xf5\x1bi\x8f\xe9h\xa7\x1b\x99\xdcdy\x0b\xa0'), (b'\xd2\xa0\x8a\xb5\xf1\x01\x1dg\x18\x00\x11\xfc\x970k\x03', b'X/\xd3\xbcq\xc6\x93\xa3Z\xe9\xf36||\xea('), (b'`\x81\xf9\xbed1\x9c\xdaCp\x85\xa0\xec5SO', b'\x16\xc1\x01\x88\xc5(\x04z\x00\x9d\t;T\x90\xd2"'), (b'4F\xe2\x91\x1f=\x93!m\x83\xf2&\xa0\x0f\x9c\xb4', b'yWc\x1f\xd3\x0c\xfaTe\xdb\xd5m\x98\x85n\xb4'), (b'2\x9c}\xeb\xe2\xc7\xc2M\xe5\xbe\x1c\x16\xffcD1', b'\xaa\xcd\xfd\xf6\xc8Iis\x17;)\xff\x15\xec\x1c\xba'), (b'\x84;\x9b\x1bS\xb78H\xbd\xe5\xa5\xf8\x99~\x1f\x10', b'\x84bT\x8c\xd6.Iq\x02\xd5\x8e\xa5!jO\x95'), (b'\xe2\xa1\x83\xd9\xd3o&5\xcc\x1d\x14\x9e\x0e\x0c4}', b'\xdc\xb2\xe4/5}"\xb7\x8c\x109\xb92\xdc\xe4T'), (b"|\x1f\x07M\x03\x8c\xder\xc8'\x9e\xec\xe6,\xe6&", b'_\x19FFC~0\xe6\xf8V\xf3(\x10\x13\xa5t'), (b'\xf1\xe8\xab\xa7{\xcd\x80>\xdd\x8d\x98\xe1\x87\xd5\xdc\xeb', b'jL\xc2\xa2|F\xb9Hw\xb7\x01\x07\xfa\x00u\xb3'), (b'\x0b\x8a}\xe7\xa8\x80\xa7\xbeh5X\x0f\x80\xfa\xebs', b'\xb6\xb1\xb8\xf7\xdf\xfa\xf6\x8dP?\x02\xe4\x91\xd9\x88E'), (b'\xb4\xc6\x0f\x16h!\x05\x8bfb\xfb\xce\xac\xf5^&', b'U\xe3\xb0\xe1\xf6?\xe6\xda\x1a#\x98q\xfdlx\x9d'), (b'q\x92\x98\xef\xd6\x1c\xc2\x11\x16G\xa9\xcb\x8f\xcdR\xc0', b'\x8e\xd3S>/\x92\x18p\xb4V!\x07h\xa4\xa4S'), (b'\xaa\x8c\xe6\xde\xcd\xe8\xa7K\x88\x1b|\xa4G\xde,\x9d', b'\xe9\x13t\xec>\xc9\x00|\xd5Vu\x8c\xde\x1f\x1dK'), (b'(\xe3xd\nS\xc0\xbf\xb6\x99X\x8a\x1c&x\x81', b'\xa9\xa1\xf0p\n\xc6\x90\xd0\xe4\x8b\xb7\xd6j\xc7\xd5\xf7'), (b'wl\xab\x19\xae\xdd\xf6\xfbT:q\xb1\xc36\xec\x80', b'\xdd\xfc 39M\xdb/\x06\xfc\x00\xe2\x94\xe6\x01a'), (b'\x0c:g\x84\xa3D+@\xc8\x96\x8c\x9bu\x82\xe4\xa9', b'c\x94\xe0\xc4R\xd7\xf1\\\xb8\xc9\x00:\xad\xbb\xff\x8e'), (b'\x94\x01\xce\xc2\x84\xd0\xc3$_\x91v\xff\xfd\x8a\x84>', b'5kD\xff\xcd\x97\x95$\xe3}\xac\x92\xc3\x1b\xcc\x0f'), (b'i\x9b\x98\xea\x92\xbd\x9c&\rh\xd5]q\x9a\xeb\x99', b'\xc9ks\xe9t\xdd[\x8e\x10\x8b\xf3~!\xddk`'), (b'\x05\x8a\xeff\x88^wF;\xd6O\x81\xa1\xfe\x01\x93', b'\xc5\x9e\xdb\xcd\xd4U\xe8p\x80\xd0O\xd6\xfe\xfex\x99'), (b'*}j\xa7\x7f\xb3\x9c4\xb4\xe1\xacH\x99]\x7fw', b'\xd8\xbd\x88\x04\x956\xb8N\x9fv\x892\x93rq\xe3'), (b'W\xebp\x99\x1e: {Hr\xc7\x95\x17rRz', b'd\x04\xd7\x1d\xf5\xc0\x0b\xe8\xa3*\xc7\xda\x0c\xab+\xad'), (b'\xe65ga\x91}\xb9\xda\x9d\x87\xfbK.\x91!4', b'\xaec_\x9b\x06\xe7\xfa\x0b\xf0\x1f\xbe\x11\x1aC\x7f\t'), (b'\xdf\xd1\xac\xab\x17JA&\xc3\xe1\xf2\x9a\xb2?\x88\xe0', b'.\xd6HK\xae\x10\xc2\xcf\xe0\x16a\xfe\xd0E5\xf8'), (b'k)\x99\xf2\xd0\xe7\x17\xa7\xf8\xe0\xe2}\xc6`\xec\xe6', b'i\xe3\xcb\x9dV\xc9\xe2\x0e!\xa4\x05\xb9\xf8qK\x90'), (b'\xf8E\x07\xf3D\xbb\xca\xf0\xe7\x0cb9\xcd8_\x00', b'q\xad\xc3\x82\x8b)\xa9\xaf\x08\x19\x9f\x86\xf1\xdc\x10\xcf'), (b'\xab\x84X[\xf3\x05\xaa~\x8f\xb9\xb6\x1dI\xb9\xc1\xb0', b'\x13\x00A\xe9\xb6\x10\xc0\x06\xd2k\xb5\xbavv\xc9o'), (b'\xca\xe5\xab\x18[\xe3\\\xec\x00T=;\x99\xfc\xc6 ', b'\xd8\x02\xf0\xe1A\x92\xcba\xef\x86\x12~\x1a\x18\xbf\xef'), (b'p\x03[\\#\xc6\xebV*\x0b\x1e\x84\x83\xb9\x06\x03', b'\xf4?1\xcaW>\xa3\xda\xf3\xe8\t\xa1\xd2\xed"\x86'), (b'\xb7\xe2p\x03\x01\x94\xb3d\x94\x11\xffG<\rKb', b'\xa0pi?\xf2~\x16\x19\xa2\x1e\x85\xcak\xf4n\xb0'), (b'u\xa0"L\xd1\xa5\x00\x19\x12<\xe7\xa9\xd7\x009\xf6', b'U\xa3\x1d\xe8\xe1*\x9e\xebQ2\x06\xff;\x87\t\xe7'), (b'\xdd\xe0\xcdr\xd0\xc1\xc2\x95\x85+E6\xddnt\x01', b'WGhT\x94D\xe5\x02WGg\xf9A\xe3z!'), (b'j9\xbb\xbe\xd7k\xb9_\xca\xd3\xcbl\xd4X\x02\xf0', b'$\xa1\x85<\x01\x97\x91w\xfe\xe3\nd\xedB\x00!'), (b'\xb71\xdbo\xddq=P\xf2\x06\xb4N\x13\xc2\x060', b'\xef\x00\xdas\xc9P}\xb0m&\x87\xe2\x18_\xf6\x9e'), (b"\x8a\x91yw'\xf0\xc2\x1f\xbc\x0f0\xaa\xda\xf0|\x15", b'\xaa\x9c\xec\xb5`\xfd\xac\x06\xd6_E\xdci%\xf3H'), (b'\xb7\xe5C\xc2\xe9\xf9h\x98\xf2\xcb\xdb\xd0k\x8a\x12\xdd', b'O~\xaf\x90\x87\xee5$\xd3\x83\x8a\xfe?\x1c\x87\x08'), (b'\xe99-\x82\xef3\x80\x06\x9d\xb9\x1c\xc5\xe1^\x1c\x90', b'\xb1\xd0\x01\xf2\x90\nF\xf5\x9f+\x8d\xea\x1d\xc4\xfb\xd8'), (b'!\x82j\xf6\xd0?\n~\xd2\xc3z\xf6xhPC', b'\xfd\xc2-\x8d\xa1J%\xe8\xe3\x9e+6\xb2\xba\x02l'), (b'H\xf2\x91\x84lA*+\x0b\xf3\xef\xc4\xa3\xc3\x87\xc6', b'\x8d,\x81\x82,P\x9f\xe3~N<\x1d\xaf\xcdY\xab')]

K = [11203608954683813621, 16493625149770257099, 14028124698329247043, 14301348153620101778, 6551721942959326409, 4762038057096388576, 3609979849505654858, 1612282650402836386,
     5936503058091595371, 9829764367442340320, 695803877269221422, 3165832863663201199, 290157554447267290, 2714347313732374281, 14592997346911623582, 2752926827304755429]


def rol(val, shift):
    return (val << shift) % (2**ARCH) | val >> (ARCH - shift)


def ror(val, shift):
    return val >> shift | (val << (ARCH - shift)) % (2**ARCH)


def mask_low(iv_low: int):
    global K

    state = iv_low
    for i in range(len(K)):
        state ^= K[i]
        state = ror(state, 38)

        state ^= K[(i+2) % len(K)]
        state = rol(state, 45)

        state ^= K[(i+4) % len(K)]
        state = ror(state, 19)

        state ^= K[(i+6) % len(K)]
        state = rol(state, 5)

        state ^= K[(i+8) % len(K)]
        state = ror(state, 27)

        state ^= K[(i+10) % len(K)]
        state = rol(state, 53)

        state ^= K[(i+12) % len(K)]
        state = ror(state, 2)

        state ^= K[(i+14) % len(K)]
        state = rol(state, 4)

    return state


def mask_high(iv_high: int):
    global K

    state = iv_high
    for i in range(len(K)):
        state ^= K[(i+1) % len(K)]
        state = ror(state, 8)

        state ^= K[(i+3) % len(K)]
        state = rol(state, 56)

        state ^= K[(i+5) % len(K)]
        state = ror(state, 23)

        state ^= K[(i+7) % len(K)]
        state = rol(state, 33)

        state ^= K[(i+9) % len(K)]
        state = ror(state, 13)

        state ^= K[(i+11) % len(K)]
        state = rol(state, 17)

        state ^= K[(i+13) % len(K)]
        state = ror(state, 44)

        state ^= K[(i+15) % len(K)]
        state = rol(state, 40)

    return state


def compute_mask(iv: bytes):
    """iv is 16 bytes long"""
    global K

    iv_low = int.from_bytes(iv[:8], "little")
    iv_high = int.from_bytes(iv[8:], "little")

    state_low = mask_low(iv_low)  # keep highest 32 bits
    state_high = mask_high(iv_high)  # keep highest 32 bits

    hi = (state_low & 0xffffffff) << 32 | state_high >> 32
    lo = (state_high & 0xffffffff) << 32 | state_low >> 32

    mask = b""
    mask += (lo).to_bytes(8, "little")
    mask += (hi).to_bytes(8, "little")

    return mask


def decrypt(ciphertext: bytes, idx: int):
    if len(ciphertext) % BLOCK_SIZE != 0:
        return "error: invalid padding"

    plain = []
    i = 0
    block = ciphertext[:BLOCK_SIZE]
    next = idx
    while block != b"":
        (key, iv) = KEYS[next]

        mask = compute_mask(iv)
        key_final = xor(key, mask)
        print(key_final, iv)

        aes = AES.new(key_final, AES.MODE_CBC, iv=iv)
        plain.append(aes.decrypt(block))

        next = compute_next_idx(plain[-1], next)
        i += 1 << 4
        block = ciphertext[i:i + BLOCK_SIZE]

    return b"".join(plain)


def compute_next_idx(plaintext: bytes, offset: int) -> int:
    h = hashlib.sha256(plaintext+SALT)
    h = h.digest()

    sum = 0
    for i in range(len(h)):
        sum += h[i]

    return ((sum+offset)*25) % len(KEYS)


if __name__ == "__main__":
    print("[+] Opening encrypted file")
    with open("./encrypted", "rb") as f:
        data = f.read()

    print("[+] Decrypting data...")
    with open("./decrypted", "wb") as f:
        f.write(decrypt(data, 25))
    print("[+] Finished !")
