import { useMemo, useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Float } from '@react-three/drei';
import * as THREE from 'three';

/**
 * SentinelLoop's 3D hero visual — a wireframe "attack surface" shell around a
 * solid core, swept by a scanning ring. It is deliberately built from cheap
 * primitives only (icosahedron, octahedron, torus — a few hundred triangles
 * total), no imported models/textures, so it never blocks first paint:
 * - Lazy-loaded from Landing.tsx (React.lazy + Suspense) — the hero section
 *   renders immediately, the canvas mounts a beat later.
 * - DPR capped at 1.5 and antialias left on since the scene is tiny.
 * - A single directional + ambient light, no shadows, no post-processing.
 */

function ScanRing() {
  const ref = useRef<THREE.Mesh>(null);
  useFrame((state) => {
    if (!ref.current) return;
    const t = state.clock.getElapsedTime();
    ref.current.position.y = Math.sin(t * 0.6) * 1.15;
    ref.current.rotation.x = Math.PI / 2;
  });
  return (
    <mesh ref={ref}>
      <torusGeometry args={[1.35, 0.014, 8, 64]} />
      <meshBasicMaterial color="#EC4899" transparent opacity={0.85} />
    </mesh>
  );
}

function CoreShield() {
  const outerRef = useRef<THREE.Mesh>(null);
  const innerRef = useRef<THREE.Mesh>(null);

  useFrame((_, delta) => {
    if (outerRef.current) outerRef.current.rotation.y += delta * 0.15;
    if (innerRef.current) innerRef.current.rotation.y -= delta * 0.22;
  });

  return (
    <group>
      {/* Outer wireframe shell — represents the scanned attack surface */}
      <mesh ref={outerRef}>
        <icosahedronGeometry args={[1.6, 1]} />
        <meshBasicMaterial color="#6366F1" wireframe transparent opacity={0.35} />
      </mesh>

      {/* Solid inner core — the "protected" asset */}
      <mesh ref={innerRef}>
        <octahedronGeometry args={[0.78, 0]} />
        <meshStandardMaterial color="#A855F7" roughness={0.25} metalness={0.35} emissive="#4338CA" emissiveIntensity={0.35} />
      </mesh>

      <ScanRing />
    </group>
  );
}

function OrbitDots() {
  // A handful of static points orbiting the core — cheap, no per-point mesh.
  const points = useMemo(() => {
    const pts: [number, number, number][] = [];
    for (let i = 0; i < 10; i++) {
      const angle = (i / 10) * Math.PI * 2;
      const r = 2.05 + (i % 3) * 0.08;
      pts.push([Math.cos(angle) * r, Math.sin(angle * 1.7) * 0.5, Math.sin(angle) * r]);
    }
    return pts;
  }, []);

  const ref = useRef<THREE.Group>(null);
  useFrame((_, delta) => {
    if (ref.current) ref.current.rotation.y += delta * 0.05;
  });

  return (
    <group ref={ref}>
      {points.map((p, i) => (
        <mesh key={i} position={p}>
          <sphereGeometry args={[0.028, 6, 6]} />
          <meshBasicMaterial color={i % 2 === 0 ? '#6366F1' : '#EC4899'} />
        </mesh>
      ))}
    </group>
  );
}

export default function ThreeHero() {
  return (
    <Canvas
      dpr={[1, 1.5]}
      gl={{ antialias: true, powerPreference: 'low-power', alpha: true }}
      camera={{ position: [0, 0, 5], fov: 42 }}
      style={{ background: 'transparent' }}
    >
      <ambientLight intensity={0.55} />
      <directionalLight position={[3, 3, 4]} intensity={1.1} />
      <Float speed={1.4} rotationIntensity={0.4} floatIntensity={0.6}>
        <CoreShield />
        <OrbitDots />
      </Float>
    </Canvas>
  );
}
