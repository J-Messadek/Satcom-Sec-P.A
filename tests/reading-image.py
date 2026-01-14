import os

def read_image_in_blocks(image_path, block_size=256):
    """
    Lit une image en mode binaire et la découpe en blocs de taille donnée.
    
    Args:
        image_path (str): Chemin vers l'image.
        block_size (int): Taille d'un bloc en octets (par défaut 256).
        
    Returns:
        List[bytes]: Liste de blocs de bytes.
    """
    # Vérifier que le fichier existe
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Fichier introuvable : {image_path}")
    
    # Lire le fichier en binaire
    with open(image_path, "rb") as f:
        data_bytes = f.read()
    
    # Découper en blocs de manière classique
    blocks = []
    i = 0
    while i < len(data_bytes):
        block = data_bytes[i:i+256]  # prendre 256 octets à partir de i
        blocks.append(block)    # ajouter le bloc à la liste
        i += 256  
    
    return blocks


# --- Exemple d'utilisation ---
image_path = os.path.join("..", "data", "input", "image_source.png")

blocks = read_image_in_blocks(image_path)

print(f"Nombre de blocs : {len(blocks)}")
print(f"Taille du premier bloc : {len(blocks[0])} octets")
