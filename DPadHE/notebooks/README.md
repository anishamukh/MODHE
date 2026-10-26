# SageMath prototypes

These are translation templates: they show the structure of ModHE and of DPad-HE, and they are not
benchmarks. The numbers that go into the thesis come from the OpenFHE code in `../openfhe-dpad/`.
What the timing cells here produce is the wall clock of one run on one machine, and that is how it
should be read.

| file | what it is |
| --- | --- |
| `01_modhe_baseline_analysis.ipynb` | ModHE on Anisha's MODHE library: keygen, relin keygen, encrypt, multiply, relinearize, decrypt |
| `02_dpad_integrated_prototype.ipynb` | DPad integrated into the ModHE code, no timing cells |
| `03_dpad_decoupled_architecture.ipynb` | DPad standalone: ModHE keys, DPad keys, then rank-down and rank-up inside `DPad_Relin` |

## Running them

SageMath was dropped from the Debian and Ubuntu repositories (Debian 13 and Ubuntu 24.04 no longer
carry it), so the official guide's conda route is the way in. It needs no Docker and, once the
kernel is registered, nothing has to be started before opening a notebook.

```
curl -L -O "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh"
bash Miniforge3-$(uname)-$(uname -m).sh      # Miniforge, conda-forge is its default channel
mamba create -n sage sage                     # SageMath 10.x, a few GB
conda activate sage
python -m sage.repl.ipython_kernel.install --user
jupyter kernelspec list                       # sagemath should show up
```

`--user` writes the kernel spec to `~/.local/share/jupyter/kernels`, where every Jupyter client
finds it without the environment being active: you pick the SageMath kernel in the notebook and
that is the whole setup.

To run a notebook from the terminal instead:

```
conda activate sage
jupyter nbconvert --to notebook --execute --inplace notebooks/01_modhe_baseline_analysis.ipynb
```

Work from `code/`, not from `code/notebooks/`: notebook 01 loads `MODHE/constants.sage` and the
other files, and the submodule sits next to the notebooks. Notebook 03 carries its own copy of the
functions and runs from any directory.

The container is the fallback if something in the conda environment fights back:

```
docker run -it --rm -v "$PWD":/home/sage/work -w /home/sage/work sagemath/sagemath:latest bash
sage -n jupyter --no-browser --ip 0.0.0.0 --port 8888     # then open http://localhost:8888
```

## The timing cells

Both notebooks wrap each operation in `measure(...)` and append the results to
`sagemath_timing.csv` in this directory, one row per operation with the parameters of the run:

```
prototype,L,MLWE,POLDEG,operation,seconds,run
modhe_baseline,7,2,16384,keygen,12.34,2026-10-16 21:05
```

One run writes one block of rows; a later run appends another block with a new timestamp, so the
scatter between runs stays visible. The phases inside `DPad_Relin` (the modular key switches, the
rank-down and rank-up steps) are not separated, because the notebook calls them as one function.
