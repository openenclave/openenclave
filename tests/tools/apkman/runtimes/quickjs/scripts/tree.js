(() => {
    'use strict';
 
    // UTF8 character-drawn tree, with options for compacting vs
    // centering parents, and for pruning out nodeless lines.
 
    const example = `
               ┌ Epsilon
       ┌─ Beta ┼─── Zeta
       │       └──── Eta
 Alpha ┼ Gamma ─── Theta
       │       ┌─── Iota
       └ Delta ┼── Kappa
               └─ Lambda`
 
    // drawTree2 :: Bool -> Bool -> Tree String -> String
    const drawTree2 = blnCompact => blnPruned => tree => {
        // Tree design and algorithm inspired by the Haskell snippet at:
        // https://doisinkidney.com/snippets/drawing-trees.html
        const
            // Lefts, Middle, Rights
            lmrFromStrings = xs => {
                const [ls, rs] = Array.from(splitAt(
                    Math.floor(xs.length / 2),
                    xs
                ));
                return Tuple3(ls, rs[0], rs.slice(1));
            },
            stringsFromLMR = lmr =>
            Array.from(lmr).reduce((a, x) => a.concat(x), []),
            fghOverLMR = (f, g, h) => lmr => {
                const [ls, m, rs] = Array.from(lmr);
                return Tuple3(ls.map(f), g(m), rs.map(h));
            };
 
        const lmrBuild = (f, w) => wsTree => {
            const
                leftPad = n => s => ' '.repeat(n) + s,
                xs = wsTree.nest,
                lng = xs.length,
                [nChars, x] = Array.from(wsTree.root);
 
            // LEAF NODE --------------------------------------
            return 0 === lng ? (
                Tuple3([], '─'.repeat(w - nChars) + x, [])
 
                // NODE WITH SINGLE CHILD -------------------------
            ) : 1 === lng ? (() => {
                const indented = leftPad(1 + w);
                return fghOverLMR(
                    indented,
                    z => '─'.repeat(w - nChars) + x + '─' + z,
                    indented
                )(f(xs[0]));
 
                // NODE WITH CHILDREN -----------------------------
            })() : (() => {
                const
                    cFix = x => xs => x + xs,
                    treeFix = (l, m, r) => compose(
                        stringsFromLMR,
                        fghOverLMR(cFix(l), cFix(m), cFix(r))
                    ),
                    _x = '─'.repeat(w - nChars) + x,
                    indented = leftPad(w),
                    lmrs = xs.map(f);
                return fghOverLMR(
                    indented,
                    s => _x + ({
                        '┌': '┬',
                        '├': '┼',
                        '│': '┤',
                        '└': '┴'
                    })[s[0]] + s.slice(1),
                    indented
                )(lmrFromStrings(
                    intercalate(
                        blnCompact ? [] : ['│'],
                        [treeFix(' ', '┌', '│')(lmrs[0])]
                        .concat(init(lmrs.slice(1)).map(
                            treeFix('│', '├', '│')
                        ))
                        .concat([treeFix('│', '└', ' ')(
                            lmrs[lmrs.length - 1]
                        )])
                    )
                ));
            })();
        };
        const
            measuredTree = fmapTree(
                v => {
                    const s = ' ' + v + ' ';
                    return Tuple(s.length, s)
                }, tree
            ),
            levelWidths = init(levels(measuredTree))
            .reduce(
                (a, level) => a.concat(maximum(level.map(fst))),
                []
            ),
            treeLines = stringsFromLMR(
                levelWidths.reduceRight(
                    lmrBuild, x => x
                )(measuredTree)
            );
        return unlines(
            blnPruned ? (
                treeLines.filter(
                    s => s.split('')
                    .some(c => !' │'.includes(c))
                )
            ) : treeLines
        );
    };
 
    // TESTS ----------------------------------------------
    const main = () => {
 
        // tree :: Tree String
        const tree = Node(
            'Alpha', [
                Node('Beta', [
                    Node('Epsilon', []),
                    Node('Zeta', []),
                    Node('Eta', [])
                ]),
                Node('Gamma', [Node('Theta', [])]),
                Node('Delta', [
                    Node('Iota', []),
                    Node('Kappa', []),
                    Node('Lambda', [])
                ])
            ]);
 
        // tree2 :: Tree Int
        const tree2 = Node(
            1,
            [
                Node(2, [
                    Node(4, []),
                    Node(5, [Node(7, [])])
                ]),
                Node(3, [
                    Node(6, [
                        Node(8, []),
                        Node(9, [])
                    ])
                ])
            ]
        );
 
        // strTrees :: String
        const strTrees = ([
            'Compacted (parents not all vertically centered):',
            drawTree2(true)(false)(tree2),
            'Fully expanded, with vertical centering:',
            drawTree2(false)(false)(tree),
            'Vertically centered, with nodeless lines pruned out:',
            drawTree2(false)(true)(tree),
        ].join('\n\n'));
 
        return (
            console.log(strTrees),
            strTrees
        );
    };
 
    // GENERIC FUNCTIONS ----------------------------------
 
    // Node :: a -> [Tree a] -> Tree a
    const Node = (v, xs) => ({
        type: 'Node',
        root: v, // any type of value (consistent across tree)
        nest: xs || []
    });
 
    // Tuple (,) :: a -> b -> (a, b)
    const Tuple = (a, b) => ({
        type: 'Tuple',
        '0': a,
        '1': b,
        length: 2
    });
 
    // Tuple3 (,,) :: a -> b -> c -> (a, b, c)
    const Tuple3 = (a, b, c) => ({
        type: 'Tuple3',
        '0': a,
        '1': b,
        '2': c,
        length: 3
    });
 
    // compose (<<<) :: (b -> c) -> (a -> b) -> a -> c
    const compose = (f, g) => x => f(g(x));
 
    // concat :: [[a]] -> [a]
    // concat :: [String] -> String
    const concat = xs =>
        0 < xs.length ? (() => {
            const unit = 'string' !== typeof xs[0] ? (
                []
            ) : '';
            return unit.concat.apply(unit, xs);
        })() : [];
 
    // fmapTree :: (a -> b) -> Tree a -> Tree b
    const fmapTree = (f, tree) => {
        const go = node => Node(
            f(node.root),
            node.nest.map(go)
        );
        return go(tree);
    };
 
    // fst :: (a, b) -> a
    const fst = tpl => tpl[0];
 
    // identity :: a -> a
    const identity = x => x;
 
    // init :: [a] -> [a]
    const init = xs =>
        0 < xs.length ? (
            xs.slice(0, -1)
        ) : undefined;
 
    // intercalate :: [a] -> [[a]] -> [a]
    // intercalate :: String -> [String] -> String
    const intercalate = (sep, xs) =>
        0 < xs.length && 'string' === typeof sep &&
        'string' === typeof xs[0] ? (
            xs.join(sep)
        ) : concat(intersperse(sep, xs));
 
    // intersperse(0, [1,2,3]) -> [1, 0, 2, 0, 3]
 
    // intersperse :: a -> [a] -> [a]
    // intersperse :: Char -> String -> String
    const intersperse = (sep, xs) => {
        const bln = 'string' === typeof xs;
        return xs.length > 1 ? (
            (bln ? concat : x => x)(
                (bln ? (
                    xs.split('')
                ) : xs)
                .slice(1)
                .reduce((a, x) => a.concat([sep, x]), [xs[0]])
            )) : xs;
    };
 
    // iterateUntil :: (a -> Bool) -> (a -> a) -> a -> [a]
    const iterateUntil = (p, f, x) => {
        const vs = [x];
        let h = x;
        while (!p(h))(h = f(h), vs.push(h));
        return vs;
    };
 
    // Returns Infinity over objects without finite length.
    // This enables zip and zipWith to choose the shorter
    // argument when one is non-finite, like cycle, repeat etc
 
    // length :: [a] -> Int
    const length = xs =>
        (Array.isArray(xs) || 'string' === typeof xs) ? (
            xs.length
        ) : Infinity;
 
    // levels :: Tree a -> [[a]]
    const levels = tree =>
        iterateUntil(
            xs => 1 > xs.length,
            ys => [].concat(...ys.map(nest)),
            [tree]
        ).map(xs => xs.map(root));
 
    // maximum :: Ord a => [a] -> a
    const maximum = xs =>
        0 < xs.length ? (
            xs.slice(1).reduce((a, x) => x > a ? x : a, xs[0])
        ) : undefined;
 
    // nest :: Tree a -> [a]
    const nest = tree => tree.nest;
 
    // root :: Tree a -> a
    const root = tree => tree.root;
 
    // splitAt :: Int -> [a] -> ([a], [a])
    const splitAt = (n, xs) =>
        Tuple(xs.slice(0, n), xs.slice(n));
 
    // unlines :: [String] -> String
    const unlines = xs => xs.join('\n');
 
    // MAIN ---
    return main();
})();
