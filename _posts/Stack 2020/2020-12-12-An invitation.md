---
title: "An invitation [981]"
tags: [Stack 2020, Reversing]
excerpt: "Reversing"
layout: single
classes: wide
--- 

**Category:** Web

## Challenge Description

> We want you to be a member of the Cyber Defense Group! Your invitation has been encoded to avoid being detected by COViD's sensors. Decipher the invitation and join in the fight!

## Starting off

Looking at `index.html`, we open it in the browser, but nothing seems to show up on the page. We view the browser console to see an undefined variable error message in `invite.js`, imported through a `<script>` tag. For `jquery-led.js`, it appears as decently well written and formatted code, with the author credited and license mentioned as well. After a little Googling, we quickly discover that it is an open-source plug-in, [here](https://webartdevelopers.com/blog/tag/jquery-led/). We can conclude these are likely not needed to be reversed, and instead it is `invite.js` that does, being related to the challenge name as well.

## Breaking down `invite.js`

Rather than handling the mess of obfuscation entirely manually, we can put it into an automatic formatter. For JavaScript, we can just use [beautifier.io](https://beautifier.io/). The beautified code looks like this:

```js
try {
    canvas = document['querySelector']('.G');
    gl = canvas['getContext']('webgl');
    gl['clearColor'](0.0, 0.0, 0.0, 1.0);
    gl['clear'](gl.COLOR_BUFFER_BIT);
    shade = canvas['getAttribute']('shade');
    ctype = canvas['getAttribute']('type');
    cid = canvas['getAttribute']('id')['slice'](5, 7);
    gl['KG'] = window[shade + cid + ctype];
} catch (err) {}

var _0x55f3 = ['||||||function|var||hhh||||for|charCodeAt|if|length|eee||uuu||mmm|||custom|fromCharCode|String|vvv||ggg|location|catLED|type||color||rounded|font_type|background_color|e0e0e0|size|return|zzz|FF0000|value|seed|yyy|rrr||ooo|slice|ttt|false|window|else|you|iii|let|YOU||compare|0xff|||23|re|hostname|console|||57|protocol|file|54|log|max|Math|98|requestAnimationFrame|true|0BB|00|88|09|0FZ|02|0D|06HD|03S|31|get|new|Image|Object|defineProperty|id|unescape|invited|2000|pathname|const|ech||setTimeout|WANT|WE|custom3|custom2|INVITED|RE|custom1|debugger|1000|invite|the|accepting|alert|Thank|indexOf|go|118|3V3jYanBpfDq5QAb7OMCcT|leaHVWaWLfhj4|atob', 'toString', 'replace', 'x=[0,0,0];1C Y=(a,b)=>{V s=\'\';d(V i=0;i<1e.1d(a.g,b.g);i++){s+=q.p((a.e(i)||0)^(b.e(i)||0))}F s};f(u.19==\'1a:\'){x[0]=12}S{x[0]=18}f(Y(R.u.14,"T\'13 1z!!!")==1y("%1E%1j%1q%17%1p%1o%1n%1m%1l%1i@M")){x[1]=1k}S{x[1]=1r}6 K(){7 j=Q;7 G=1t 1u();1v.1w(G,\'1x\',{1s:6(){j=1h;x[2]=1b}});1g(6 X(){j=Q;15.1c("%c",G);f(!j){x[2]=1f}})};K();6 N(J){7 m=Z;7 a=11;7 c=17;7 z=J||3;F 6(){z=(a*z+c)%m;F z}}6 U(h){P=h[0]<<16|h[1]<<8|h[2];L=N(P);t=R.u.1B.O(1);9="";d(i=0;i<t.g;i++){9+=q.p(t.e(i)-1)}r=1Z("1X//k/1Y=");l="";f(9.O(0,2)=="1V"&&9.e(2)==1W&&9.1U(\'1D-c\')==4){d(i=0;i<r.g;i++){l+=q.p(r.e(i)^L())}1S("1T T d 1R 1Q 1P!\n"+9+l)}}d(a=0;a!=1O;a++){1N}$(\'.1M\').v({w:\'o\',y:\'#H\',C:\'#D\',E:10,A:5,B:4,I:" W\'1L 1K! "});$(\'.1J\').v({w:\'o\',y:\'#H\',C:\'#D\',E:10,A:5,B:4,I:"                 "});$(\'.1I\').v({w:\'o\',y:\'#H\',C:\'#D\',E:10,A:5,B:4,I:"   1H 1G W!  "});1F(6(){U(x)},1A);', '\w+'];

(function(_0x92e4x2, _0x92e4x3) {
    var _0x92e4x4 = function(_0x92e4x5) {
        while (--_0x92e4x5) {
            _0x92e4x2['push'](_0x92e4x2['shift']());
        }
    };
    _0x92e4x4(++_0x92e4x3);
}(_0x55f3, 0x65));

var _0x3db8 = function(_0x92e4x2, _0x92e4x3) {
    _0x92e4x2 = _0x92e4x2 - 0x0;
    var _0x92e4x4 = _0x55f3[_0x92e4x2];
    return _0x92e4x4;
};
var _0x27631a = _0x3db8;

gl['KG'](function(_0x92e4x5, _0x92e4x8, _0x92e4x9, _0x92e4xa, _0x92e4xb, _0x92e4xc) {
    var _0x92e4xd = _0x3db8;
    _0x92e4xb = function(_0x92e4xe) {
        var _0x92e4xf = _0x3db8;
        return (_0x92e4xe < _0x92e4x8 ? '' : _0x92e4xb(parseInt(_0x92e4xe / _0x92e4x8))) + ((_0x92e4xe = _0x92e4xe % _0x92e4x8) > 0x23 ? String['fromCharCode'](_0x92e4xe + 0x1d) : _0x92e4xe[_0x92e4xf('0x0')](0x24));
    };
    if (!'' [_0x92e4xd('0x1')](/^/, String)) {
        while (_0x92e4x9--) {
            _0x92e4xc[_0x92e4xb(_0x92e4x9)] = _0x92e4xa[_0x92e4x9] || _0x92e4xb(_0x92e4x9);
        }
        _0x92e4xa = [function(_0x92e4x10) {
            return _0x92e4xc[_0x92e4x10];
        }], _0x92e4xb = function() {
            var _0x92e4x11 = _0x92e4xd;
            return _0x92e4x11('0x3');
        }, _0x92e4x9 = 0x1;
    };
    while (_0x92e4x9--) {
        _0x92e4xa[_0x92e4x9] && (_0x92e4x5 = _0x92e4x5[_0x92e4xd('0x1')](new RegExp('\b' + _0x92e4xb(_0x92e4x9) + '\b', 'g'), _0x92e4xa[_0x92e4x9]));
    }
    return _0x92e4x5;
}(_0x27631a('0x2'), 0x3e, 0x7c, _0x27631a('0x4')['split']('|'), 0x0, {}));
```

Other than formatting the code, the beautifier also did some variable substitutions for us, saving us some effort. To summarise what the code does:

- `try` setting `gl.KG` to a global `window` variable
- declare a (rather large) string array variable `_0x55f3`
- some array methods on the above string array
- declare a helper function, assigned to both `_0x3db8` and `_0x27631a`
- call `gl.KG` as a function on an IIFE (immediately-invoked function expression)

The undefined variable error found in the browser console when opening `index.html`, is in fact for `gl`, which means the `try` block had failed. The attributes of some elements provided in DOM (Document Object Model) of `index.html` don't match up exactly with what `invite.js` requires. As there are only a limited number of possible global functions, in `window`, we can try to figure out what the function `gl.KG` was intended to be. A good way to do this is to look into the IIFE that was called as the argument of `gl.KG`.

## Analysing the IIFE

Before starting, we remove the `try` block, and put the IIFE into `console.log`, so we can run the Javscript as we wish. Rather than analysing from top to bottom, we trace backwards starting from the return value, `_0x92e4x5`. The only places that this variable appears in the IIFE are as the first parameter, in an assignment in the `while` loop just before returning, and of course in the return value itself. We don't need to deal with the rest of the IIFE. (Though note that during the actual CTF, I _did_ reverse much more of the code to get a good handle on what it really does.)

With a little `console.log`-ing, we find that the `while` loop runs for exactly one iteration, and the assignment of `_0x92e4x5` does occur. The `.replace(regex, callback)` method on `String.prototype` is called on the string `_0x92e4x5`. The _intended_ regex takes word bounds, `'\b'` from the argument of the `RegExp` constructor, and the `'\w+'` from the string array, with a global flag `'g'`, forming the regex `/\b\w+\b/`. However, one well-known caveat of the `RegExp` constructor, from past experience dealing with JavaScript regexes, is the escaping. The backslashes on the word bound `\b` and word character `\w` character classes, would appear in the raw regex literal, they would have to be escaped (as `\\`) when in a string passed to the `RegExp` constructor. Simply inserting this double backslash in all three places, and running the code again, we have the argument passed to the IIFE:

```javascript
x=[0,0,0];const compare=(a,b)=>{let s='';for(let i=0;i<Math.max(a.length,b.length);i++){s+=String.fromCharCode((a.charCodeAt(i)||0)^(b.charCodeAt(i)||0))}return s};if(location.protocol=='file:'){x[0]=23}else{x[0]=57}if(compare(window.location.hostname,"you're invited!!!")==unescape("%1E%00%03S%17%06HD%0D%02%0FZ%09%0BB@M")){x[1]=88}else{x[1]=31}function yyy(){var uuu=false;var zzz=new Image();Object.defineProperty(zzz,'id',{get:function(){uuu=true;x[2]=54}});requestAnimationFrame(function X(){uuu=false;console.log("%c",zzz);if(!uuu){x[2]=98}})};yyy();function ooo(seed){var m=0xff;var a=11;var c=17;var z=seed||3;return function(){z=(a*z+c)%m;return z}}function iii(eee){ttt=eee[0]<<16|eee[1]<<8|eee[2];rrr=ooo(ttt);ggg=window.location.pathname.slice(1);hhh="";for(i=0;i<ggg.length;i++){hhh+=String.fromCharCode(ggg.charCodeAt(i)-1)}vvv=atob("3V3jYanBpfDq5QAb7OMCcT//k/leaHVWaWLfhj4=");mmm="";if(hhh.slice(0,2)=="go"&&hhh.charCodeAt(2)==118&&hhh.indexOf('ech-c')==4){for(i=0;i<vvv.length;i++){mmm+=String.fromCharCode(vvv.charCodeAt(i)^rrr())}alert("Thank you for accepting the invite!
"+hhh+mmm)}}for(a=0;a!=1000;a++){debugger}$('.custom1').catLED({type:'custom',color:'#FF0000',background_color:'#e0e0e0',size:10,rounded:5,font_type:4,value:" YOU'RE INVITED! "});$('.custom2').catLED({type:'custom',color:'#FF0000',background_color:'#e0e0e0',size:10,rounded:5,font_type:4,value:"                 "});$('.custom3').catLED({type:'custom',color:'#FF0000',background_color:'#e0e0e0',size:10,rounded:5,font_type:4,value:"   WE WANT YOU!  "});setTimeout(function(){iii(x)},2000);
```

Now it would be sufficiently clear: This is more JavaScript code; the global function `gl.KG` that we want is just `eval()`. In the browser console, it merely gives a decoration on the page, and pauses midway in the debugger. Removing the `debugger` statement, a message appears through the `jquery-led.js` plug-in - but still no sign of the flag. Perhaps we need to take a closer look at the code rather than a cursory skim. Again, into [beautifier.io](https://beautifier.io/) it goes.

```js 
x = [0, 0, 0];
const compare = (a, b) => {
    let s = '';
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        s += String.fromCharCode((a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0));
    }
    return s;
};
if (location.protocol == 'file:') {
    x[0] = 23;
} else {
    x[0] = 57;
}
if (compare(window.location.hostname, "you're invited!!!") == unescape("%1E%00%03S%17%06HD%0D%02%0FZ%09%0BB@M")) {
    x[1] = 88;
} else {
    x[1] = 31;
}

function yyy() {
    var uuu = false;
    var zzz = new Image();
    Object.defineProperty(zzz, 'id', {
        get: function() {
            uuu = true;
            x[2] = 54;
        }
    });
    requestAnimationFrame(function X() {
        uuu = false;
        console.log("%c", zzz);
        if (!uuu) {
            x[2] = 98;
        }
    })
};
yyy();

function ooo(seed) {
    var m = 0xff;
    var a = 11;
    var c = 17;
    var z = seed || 3;
    return function() {
        z = (a * z + c) % m;
        return z;
    }
}

function iii(eee) {
    ttt = eee[0] << 16 | eee[1] << 8 | eee[2];
    rrr = ooo(ttt);
    ggg = window.location.pathname.slice(1);
    hhh = "";
    for (i = 0; i < ggg.length; i++) {
        hhh += String.fromCharCode(ggg.charCodeAt(i) - 1)
    }
    vvv = atob("3V3jYanBpfDq5QAb7OMCcT//k/leaHVWaWLfhj4=");
    mmm = "";
    if (hhh.slice(0, 2) == "go" && hhh.charCodeAt(2) == 118 && hhh.indexOf('ech-c') == 4) {
        for (i = 0; i < vvv.length; i++) {
            mmm += String.fromCharCode(vvv.charCodeAt(i) ^ rrr())
        }
        alert("Thank you for accepting the invite!"+hhh+mmm);
    }
}

// for(a=0;a!=1000;a++) { debugger }

$('.custom1').catLED({type:'custom',color:'#FF0000',background_color:'#e0e0e0',size:10,rounded:5,font_type:4,value:"YOU 'RE INVITED! "});
$('.custom2').catLED({type:'custom',color:'#FF0000',background_color:'#e0e0e0',size:10,rounded:5,font_type:4,value:"                 "});
$('.custom3').catLED({type:'custom',color:'#FF0000',background_color:'#e0e0e0',size:10,rounded:5,font_type:4,value:"   WE WANT YOU!  "});
setTimeout(function(){iii(x)},2000);
```

This time it is helpful to go through the code progressively. First a length 3 array `x[]` has its elements assigned:
- `x[0]` is set to 23 or 57
- `x[1]` is set to 88 or 31
- `x[2]` is set to 54 or 98

The function `iii()` is called on the array `x[]` through a `setTimeout()`. Within it, we see an `alert()` that gives user interaction, we can expect that this is where we finish, and get the flag, so we seek to find the values of `hhh` and `mmm`. For `hhh`, a check is performed to ensure it starts with `"gov*ech-c"` where the asterisk is any character. This is just part of the flag format, so the important bit comes from `mmm`. We can remove the parts involving `hhh` and `ggg`, then run the code on each of the 8 possible arrays `x[]`, `console.log`-ing the value of `mmm` each time. The array `[57,88,54]` is the only one that gives a readable string for `mmm`: `{gr33tz_w3LC0m3_2_dA_t3@m_m8}`

**Flag:** `govtech-csg{gr33tz_w3LC0m3_2_dA_t3@m_m8}`
