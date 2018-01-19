# CMAKE-script to wrap sources with pre- and suffix (all files)
#
# Args:
# - WRAP_DST - Output file
# - WRAP_SRC - Input file
# - WRAP_PRE - Prefix file
# - WRAP_SUF - Suffix file
#
# Reulting file (WRAP_DST) will be the contents of WRAP_PRE, WRAP_SRC, WRAP_SUF

function(wrap output input pre post)
	file(READ ${pre} pre_cont)
	file(READ ${input} input_cont)
	file(READ ${post} post_cont)

	file(WRITE ${output} "${pre_cont}")
	file(APPEND ${output} "${input_cont}")
	file(APPEND ${output} "${post_cont}")
endfunction(wrap)

wrap(${WRAP_DST} ${WRAP_SRC} ${WRAP_PRE} ${WRAP_SUF})
