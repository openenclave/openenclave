(() => {
    'use strict';
 
    // sierpinski :: Int -> String
    const sierpinski = n =>
        Array.from({
            length: n
        })
        .reduce(
            (xs, _, i) => {
                const s = ' '.repeat(Math.pow(2, i));
                return xs.map(x => s + x + s)
                    .concat(
                        xs.map(x => x + ' ' + x)
                    )
            },
            ['*']
        ).join('\n');
 
    // TEST -------------------------------------------
    console.log(
        sierpinski(4)
    );
})();
