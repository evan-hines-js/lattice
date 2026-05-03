#!/bin/bash
rsync -az --delete --exclude='target' ../lattice/ ubuntu@10.0.0.17:~/lattice/
