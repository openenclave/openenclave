#!/bin/sh
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -v
echo "Cleaning outputs"
rm ./*.ppm ./*.wav 2>/dev/null
#-------------------------------------------------------------------------------------------



echo "Running mandelbrot benchmark"
host/wasm_host enc/wasm_enc "$PWD/enc/benchmark/mandelbrot/mandel.wasm" 300 500 > mandel.ppm
echo "Benchmark complete"
echo "Type 'firefox mandel.ppm' to view generated image"
#-------------------------------------------------------------------------------------------



echo "Running ray-tracing benchmark"
cat "$PWD/enc/benchmark/c-ray/scene" 
host/wasm_host enc/wasm_enc "$PWD/enc/benchmark/c-ray/c-ray.wasm" \
	       < "$PWD/enc/benchmark/c-ray/scene" \
	       > scene.ppm
echo "Benchmark complete"
echo "Type 'firefox scene.ppm' to view generated image"
#-------------------------------------------------------------------------------------------



if command -v sox; then
  echo "Running synthesizer benchmark"
  host/wasm_host enc/wasm_enc "$PWD/enc/benchmark/wasmsynth/webchip-music.wasm" \
      | sox -S -t raw -b 32 -e float -r 44100 -c 2 - webchip.wav &
  synth_pid=$!
  sleep 15 && kill -KILL $synth_pid
  echo "Benchmark complete"
  echo "Type 'play webchip.wav' or 'firefox webchip.wav' to play generate music"
fi
#-------------------------------------------------------------------------------------------


