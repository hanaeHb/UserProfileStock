package com.example.usersservice.web;

import com.example.usersservice.DTO.UserRequest;
import com.example.usersservice.DTO.UserResponce;
import com.example.usersservice.entities.MetierRole;
import com.example.usersservice.entities.ProfileStatus;
import com.example.usersservice.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "User Profiles", description = "API pour la gestion des profils internes")
@RestController
@RequestMapping("/v1/user-profiles")
public class UserController {

    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @Operation(
            summary = "Créer un nouveau profil interne (Admin ou user profil)",
            description = "Crée un profil pour l'utilisateur interne connecté (userId extrait du token)"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Profil créé avec succès"),
            @ApiResponse(responseCode = "409", description = "Le profil existe déjà")
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<UserResponce> createUserProfile(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody UserRequest request,
            @RequestParam(required = false) Integer userIdParam) {

        Integer userId;
        List<String> roles = jwt.getClaim("roles");
        if (userIdParam != null) { // Admin spécifie un userId
            if (!roles.contains("ADMIN")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            userId = userIdParam;
        } else { // Utilisateur normal
            userId = ((Long) jwt.getClaim("userId")).intValue();

        }
        String nom = jwt.getClaim("nom");
        String prenom = jwt.getClaim("prenom");
        String email = jwt.getClaim("email");
        String phone = jwt.getClaim("phone");
        String cin = jwt.getClaim("cin");
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createUserProfile(userId,nom,prenom,email, phone, cin, request));
    }

    @Operation(summary = "Mettre à jour un profil interne existant (Admin ou user profil)",
            description = "Met à jour les informations personnelles et métier du profil interne")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profil mis à jour avec succès"),
            @ApiResponse(responseCode = "404", description = "Profil non trouvé")
    })

    @PreAuthorize(
            "authentication.principal.claims['roles'].contains('ADMIN') or " +
                    "authentication.principal.claims['roles'].contains('Manager') or " +
                    "authentication.principal.claims['roles'].contains(' PROCUREMENT_MANAGER') or " +
                    "authentication.principal.claims['roles'].contains('InventoryManager')"
    )
    @PutMapping("/me")
    public ResponseEntity<UserResponce> updateMyProfilePartial(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody UserRequest request) {

        Integer userId = ((Long) jwt.getClaim("userId")).intValue();

        return ResponseEntity.ok(service.updateUserProfile(userId, request));
    }

    @Operation(summary = "Obtenir mon profil interne (user profil)",
            description = "Retourne le profil complet de l'utilisateur connecté")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profil récupéré avec succès"),
            @ApiResponse(responseCode = "404", description = "Profil non trouvé")
    })

    @PreAuthorize(
            "authentication.principal.claims['roles'].contains('ADMIN') or " +
                    "authentication.principal.claims['roles'].contains('Manager') or " +
                    "authentication.principal.claims['roles'].contains('PROCUREMENT_MANAGER') or " +
                    "authentication.principal.claims['roles'].contains('InventoryManager')"
    )
    @GetMapping("/me")
    public ResponseEntity<UserResponce> getMyProfile(@AuthenticationPrincipal Jwt jwt) {

        Integer userId = ((Long) jwt.getClaim("userId")).intValue();
        String nom = jwt.getClaim("nom");
        String prenom = jwt.getClaim("prenom");
        String email = jwt.getClaim("email");
        String phone = jwt.getClaim("phone");
        String cin = jwt.getClaim("cin");

        List<String> roles = jwt.getClaim("roles");

        String mainRole = roles.get(0);
        MetierRole jwtRole;
        try {
            jwtRole = MetierRole.valueOf(mainRole.toUpperCase().replace(" ", "_"));
        } catch (IllegalArgumentException e) {

            jwtRole = MetierRole.DEFAULT;
        }

        UserResponce profile;

        try {
            profile = service.getUserProfileById(userId);
            if (profile.getMetierRole() != jwtRole) {
                service.updateMetierRole(userId, jwtRole);
                profile.setMetierRole(jwtRole);
            }

        } catch (RuntimeException e) {
            UserRequest request = new UserRequest();
            request.setMetierRole(jwtRole);

            profile = service.createUserProfile(
                    userId,
                    nom != null ? nom : "Inconnu",
                    prenom != null ? prenom : "Inconnu",
                    email,
                    phone,
                    cin,
                    request
            );
        }

        return ResponseEntity.ok(profile);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@AuthenticationPrincipal Jwt jwt) {
        Integer userId = ((Long) jwt.getClaim("userId")).intValue();

        service.updateProfileStatus(userId, ProfileStatus.OUT_WORK);

        return ResponseEntity.ok("Utilisateur déconnecté, status OUT_WORK");
    }

    @Operation(summary = "Lister tous les profils internes(Admin)",
            description = "Retourne la liste complète des profils internes existants")
    @ApiResponse(responseCode = "200", description = "Liste des profils récupérée avec succès")

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<List<UserResponce>> getAllUserProfiles(
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(service.getAllUserProfiles(jwt));
    }

    @Operation(summary = "Supprimer profil interne (Admin)",
            description = "Supprime le profil de l'utilisateur connecté")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profil supprimé avec succès"),
            @ApiResponse(responseCode = "404", description = "Profil non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping
    public ResponseEntity<String> deleteMyProfile(@AuthenticationPrincipal Jwt jwt) {
        Integer userId = jwt.getClaim("userId");
        service.deleteUserProfile(userId);
        return ResponseEntity.ok("Profil interne supprimé avec succès.");
    }

    @Operation(summary = "Changer le statut d'un profil interne (Admin)",
            description = "Permet à un admin de valider ou rejeter un profil interne")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Statut du profil mis à jour"),
            @ApiResponse(responseCode = "400", description = "Status invalide"),
            @ApiResponse(responseCode = "404", description = "Profil non trouvé")
    })


    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{userId}/status")
    public ResponseEntity<UserResponce> changeProfileStatus(
            @PathVariable Integer userId,
            @Parameter(description = "Nouveau statut : DRAFT, PENDING, VALIDATED, REJECTED", required = true)
            @RequestParam String status,
            @Parameter(description = "ID de l'administrateur validant/rejetant le profil", required = true)
            @RequestParam Integer adminId,
            @Parameter(description = "Raison du rejet si applicable")
            @RequestParam(required = false) String rejectionReason) {

        return ResponseEntity.ok(service.changeProfileStatus(userId, status, adminId, rejectionReason));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<String> deleteProfileByUserId(@PathVariable Integer userId) {
        service.deleteUserProfile(userId);
        return ResponseEntity.ok("Profil supprimé");
    }
}


